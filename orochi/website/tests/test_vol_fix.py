"""Tests for compose/local/vol_fix: volatility3 automagic/linux.py merged with AArch64 support (#1088).

The patched modules are loaded from the repository without touching the installed volatility3.
"""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from volatility3.framework.layers import intel

VOL_FIX = Path(__file__).resolve().parents[3] / "compose" / "local" / "vol_fix"


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def vol_linux():
    import volatility3.framework.layers as layers_pkg

    saved = sys.modules.get("volatility3.framework.layers.arm")
    arm = _load("volatility3.framework.layers.arm", VOL_FIX / "arm.py")
    sys.modules["volatility3.framework.layers.arm"] = arm
    layers_pkg.arm = arm
    try:
        yield _load("orochi_vol_fix_linux", VOL_FIX / "linux.py")
    finally:
        if saved is None:
            sys.modules.pop("volatility3.framework.layers.arm", None)
            del layers_pkg.arm
        else:
            sys.modules["volatility3.framework.layers.arm"] = saved


class FakeSymbol:
    def __init__(self, address, count=None):
        self.address = address
        self.type = SimpleNamespace(count=count)


class FakeTable:
    def __init__(self, symbols):
        self.symbols = symbols

    def get_symbol(self, name):
        return self.symbols[name]


class FakeLayer:
    def __init__(self, context, config_path, name, metadata):
        self.config = {}
        self.destroyed = False

    def destroy(self):
        self.destroyed = True


def _run_intel_substacker(vol_linux, monkeypatch, symbols, kaslr_shift=0):
    built = {}

    class Parent:
        @staticmethod
        def find_aslr(*args, **kwargs):
            return kaslr_shift, 0

        @staticmethod
        def verify_translation_by_banner(**kwargs):
            return True

    for name in ("LinuxIntel", "LinuxIntelPAE", "LinuxIntel32e"):
        layer_cls = type(name, (FakeLayer,), {})
        monkeypatch.setattr(vol_linux.intel, name, layer_cls)

    context = SimpleNamespace(config={})
    symbols.setdefault("linux_banner", FakeSymbol(0xFFFFFFFF82000000))
    layer = vol_linux.LinuxIntelSubStacker(Parent).stack(
        context=context,
        layer_name="base",
        table=FakeTable(symbols),
        table_name="t",
        config_path="cfg",
        new_layer_name="new",
        banner=b"Linux version",
    )
    built["layer"] = layer
    built["dtb"] = context.config["cfg.page_map_offset"]
    return built


def test_stack_order_and_compat_alias(vol_linux):
    assert vol_linux.LinuxIntelVMCOREINFOStacker.stack_order < vol_linux.LinuxStacker.stack_order
    # Upstream name still importable by third party code
    assert vol_linux.LinuxIntelStacker is vol_linux.LinuxStacker


def test_x64_uses_linux_specific_intel_layer(vol_linux, monkeypatch):
    built = _run_intel_substacker(vol_linux, monkeypatch, {"init_top_pgt": FakeSymbol(0xFFFFFFFF8260A000)})
    assert type(built["layer"]).__name__ == "LinuxIntel32e"
    # No KASLR shift found: fall back to the __START_KERNEL_map translation
    assert built["dtb"] == 0x260A000


def test_x86_pae_detected_through_pkmap_count(vol_linux, monkeypatch):
    symbols = {"pkmap_count": FakeSymbol(0xC1000000, count=512), "swapper_pg_dir": FakeSymbol(0xC1A00000)}
    built = _run_intel_substacker(vol_linux, monkeypatch, symbols)
    assert type(built["layer"]).__name__ == "LinuxIntelPAE"
    assert built["dtb"] == 0x1A00000


def test_x86_without_pae(vol_linux, monkeypatch):
    built = _run_intel_substacker(vol_linux, monkeypatch, {"swapper_pg_dir": FakeSymbol(0xC1A00000)})
    assert type(built["layer"]).__name__ == "LinuxIntel"


def test_kaslr_shift_is_physical_minus_virtual(vol_linux, monkeypatch):
    virtual = 0xFFFFFFFF8260A000
    physical = 0x1E60A000
    built = _run_intel_substacker(
        vol_linux, monkeypatch, {"init_top_pgt": FakeSymbol(virtual)}, kaslr_shift=physical - virtual
    )
    assert built["dtb"] == physical


def test_virtual_to_physical_address(vol_linux):
    convert = vol_linux.LinuxIntelSubStacker.virtual_to_physical_address
    assert convert(0xFFFFFFFF81000000) == 0x1000000
    assert convert(0xC1000000) == 0x1000000
    assert vol_linux.LinuxStacker.virtual_to_physical_address(0xFFFFFFFF81000000) == 0x1000000


def test_vmcoreinfo_dtb_uses_intel_translation(vol_linux):
    vmcoreinfo = {"SYMBOL(swapper_pg_dir)": 0xFFFFFFFF8260A000}
    dtb = vol_linux.LinuxIntelVMCOREINFOStacker._vmcoreinfo_get_dtb(vmcoreinfo, 0x1000000, 0x5000000)
    assert dtb == 0x260A000 - 0x1000000 + 0x5000000


def test_never_stacks_on_translated_layers(vol_linux):
    context = SimpleNamespace(layers={"l": object.__new__(intel.Intel32e)})
    assert vol_linux.LinuxStacker.stack(context, "l") is None
    assert vol_linux.LinuxIntelVMCOREINFOStacker.stack(context, "l") is None
