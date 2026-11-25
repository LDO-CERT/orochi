"""Unit tests for Volatility 3 plugin execution speedups in volatility_dask_elk."""

from types import SimpleNamespace

from volatility3.framework import automagic, contexts

from orochi.utils import volatility_dask_elk as vde


def test_choose_os_automagics_and_stackers_scopes_custom_plugin():
    class FakeCustomLinuxPlugin:
        __module__ = "volatility3.plugins.custom.linux_arp"
        __name__ = "Arp"

    ctx = contexts.Context()
    available = automagic.available(ctx)
    dump_obj = SimpleNamespace(operating_system="Linux")
    plugin_obj = SimpleNamespace(operating_system="Linux")

    chosen_ams, chosen_stackers = vde._choose_os_automagics_and_stackers(
        available, FakeCustomLinuxPlugin, dump_obj=dump_obj, plugin_obj=plugin_obj
    )
    am_names = {type(a).__name__ for a in chosen_ams}
    assert "LinuxSymbolFinder" in am_names
    assert "KernelPDBScanner" not in am_names
    assert "MacSymbolFinder" not in am_names
    assert "WinSwapLayers" not in am_names
    assert "WindowsIntelStacker" not in chosen_stackers


def test_vol3_config_cache_save_load_apply_and_invalidate(tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    dump_dir = tmp_path / "dump-cache-test"
    dump_dir.mkdir()
    dump_file = dump_dir / "sample.bin"
    dump_file.write_bytes(b"fake-dump-data")
    isf_file = tmp_path / "linux.json.xz"
    isf_file.write_bytes(b"fake-isf")

    dump_obj = SimpleNamespace(index="dump-cache-test", operating_system="Linux")

    class FakeConstructed:
        def build_configuration(self):
            return {
                "pid": [1234],
                "dump": True,
                "kernel.class": "volatility3.framework.contexts.Module",
                "kernel.offset": 0,
                "kernel.layer_name.class": "volatility3.framework.layers.intel.LinuxIntel32e",
                "kernel.layer_name.page_map_offset": 123456,
                "kernel.symbol_table_name.isf_url": f"file://{isf_file}",
            }

    vde._save_vol3_config_cache(dump_obj, str(dump_file), FakeConstructed())
    loaded = vde._load_vol3_config_cache(dump_obj, str(dump_file))
    assert loaded is not None
    assert "pid" not in loaded
    assert "dump" not in loaded
    assert loaded["kernel.layer_name.page_map_offset"] == 123456

    # Apply to a kernel-requiring plugin
    class KernelPlugin:
        @classmethod
        def get_requirements(cls):
            return [SimpleNamespace(name="kernel")]

    ctx = contexts.Context()
    assert vde._apply_cached_vol3_config(ctx, KernelPlugin, "plugins.Test", loaded) is True
    assert ctx.config["plugins.Test.kernel.layer_name.page_map_offset"] == 123456

    # Apply to a primary-only plugin (derived from kernel.layer_name.*)
    class PrimaryPlugin:
        @classmethod
        def get_requirements(cls):
            return [SimpleNamespace(name="primary")]

    ctx2 = contexts.Context()
    assert vde._apply_cached_vol3_config(ctx2, PrimaryPlugin, "plugins.Yara", loaded) is True
    assert ctx2.config["plugins.Yara.primary.page_map_offset"] == 123456

    # Missing ISF invalidates load
    isf_file.unlink()
    assert vde._load_vol3_config_cache(dump_obj, str(dump_file)) is None

    # Restore ISF, then explicit invalidation deletes cache
    isf_file.write_bytes(b"fake-isf")
    assert vde._load_vol3_config_cache(dump_obj, str(dump_file)) is not None
    vde.invalidate_vol3_config_cache(dump_obj.index)
    assert vde._load_vol3_config_cache(dump_obj, str(dump_file)) is None


def test_ensure_volatility_plugins_imported_memoizes(monkeypatch):
    calls = []
    monkeypatch.setattr(vde, "_VOL3_PLUGINS_IMPORT_SIGNATURE", None)
    monkeypatch.setattr(vde, "_plugins_path_signature", lambda: (("fake", 1),))
    monkeypatch.setattr(vde.framework, "import_files", lambda *a, **kw: calls.append(1) or [])
    monkeypatch.setattr(vde.framework, "list_plugins", lambda: {"dummy": object})

    vde._ensure_volatility_plugins_imported()
    vde._ensure_volatility_plugins_imported()
    assert len(calls) == 1

    # Changing plugin directory signature triggers a re-import
    monkeypatch.setattr(vde, "_plugins_path_signature", lambda: (("fake", 2),))
    vde._ensure_volatility_plugins_imported()
    assert len(calls) == 2
