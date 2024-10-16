# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Module to identify the Directory Table Base and architecture of windows
memory images.

This module contains a PageMapScanner that scans a physical layer to identify self-referential pointers.
All windows versions include a self-referential pointer in their Directory Table Base's top table, in order to
have a single offset that will allow manipulation of the page tables themselves.

In older windows version the self-referential pointer was at a specific fixed index within the table,
which was different for each architecture.  In very recent Windows versions, the self-referential pointer
index has been randomized, so a different heuristic must be used.  In these versions of windows it was found
that the physical offset for the DTB was always within the range of 0x1a0000 to 0x1b0000.  As such, a search
for any self-referential pointer within these pages gives a high probability of being an accurate DTB.

The self-referential indices for older versions of windows are listed below:

    +--------------+-------+
    | Architecture | Index |
    +==============+=======+
    | x86          | 0x300 |
    +--------------+-------+
    | PAE          | 0x3   |
    +--------------+-------+
    | x64          | 0x1ED |
    +--------------+-------+
"""
import json
import logging
import struct
from typing import Generator, Iterable, List, Optional, Tuple, Type

from volatility3.framework import constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import path_join
from volatility3.framework.layers import arm, intel

vollog = logging.getLogger(__name__)


class DtbSelfReferential:
    """A generic DTB test which looks for a self-referential pointer at *any*
    index within the page."""

    def __init__(
        self,
        layer_type: Type[intel.Intel],
        ptr_struct: str,
        mask: int,
        valid_range: Iterable[int],
        reserved_bits: int,
    ) -> None:
        self.layer_type = layer_type
        self.ptr_struct = ptr_struct
        self.ptr_size = struct.calcsize(ptr_struct)
        self.mask = mask
        self.page_size: int = layer_type.page_size
        self.valid_range = valid_range
        self.reserved_bits = reserved_bits

    def __call__(
        self, data: bytes, data_offset: int, page_offset: int
    ) -> Optional[Tuple[int, int]]:
        page = data[page_offset : page_offset + self.page_size]
        if not page:
            return None
        ref_pages = set()

        for ref in range(0, self.page_size, self.ptr_size):
            ptr_data = page[ref : ref + self.ptr_size]
            (ptr,) = struct.unpack(self.ptr_struct, ptr_data)
            # For both Intel-32e, bit 7 is reserved (more are reserved in PAE), so if that's ever set,
            # we can move on
            if (ptr & self.reserved_bits) and (ptr & 0x01):
                return None
            if ((ptr & self.mask) == (data_offset + page_offset)) and (
                data_offset + page_offset > 0
            ):
                # Pointer must be valid
                if ptr & 0x01:
                    ref_pages.add(ref)

        # The DTB is extremely unlikely to refer back to itself. so the number of reference should always be exactly 1
        if len(ref_pages) == 1:
            ref_page = ref_pages.pop()
            if (ref_page // self.ptr_size) in self.valid_range:
                return (data_offset + page_offset), ref_page
        return None


class DtbSelfRef32bit(DtbSelfReferential):
    def __init__(self):
        super().__init__(
            layer_type=intel.WindowsIntel,
            ptr_struct="I",
            mask=0xFFFFF000,
            valid_range=[0x300],
            reserved_bits=0x0,
        )


class DtbSelfRef64bit(DtbSelfReferential):
    def __init__(self) -> None:
        super().__init__(
            layer_type=intel.WindowsIntel32e,
            ptr_struct="Q",
            mask=0x3FFFFFFFFFF000,
            valid_range=range(0x100, 0x1FF),
            reserved_bits=0x80,
        )


class DtbSelfRef64bitOldWindows(DtbSelfReferential):
    def __init__(self) -> None:
        super().__init__(
            layer_type=intel.WindowsIntel32e,
            ptr_struct="Q",
            mask=0x3FFFFFFFFFF000,
            valid_range=[0x1ED],
            reserved_bits=0x80,
        )


class DtbSelfRefPae(DtbSelfReferential):
    def __init__(self) -> None:
        super().__init__(
            layer_type=intel.WindowsIntelPAE,
            ptr_struct="Q",
            valid_range=[0x3],
            mask=0x3FFFFFFFFFF000,
            reserved_bits=0x0,
        )

    @staticmethod
    def _and_bytes(abytes, bbytes):
        return bytes([a & b for a, b in zip(abytes[::-1], bbytes[::-1])][::-1])

    def __call__(
        self, data: bytes, data_offset: int, page_offset: int
    ) -> Optional[Tuple[int, int]]:
        dtb = super().__call__(data, data_offset, page_offset)
        if dtb:
            # Find the top page
            top_pae_page = dtb[0] - 0x4000
            # The top page should map to the next four pages after it
            # Build what we expect the page table to be
            expected_table = b"".join(
                [
                    struct.pack(
                        self.ptr_struct, top_pae_page + (i * self.layer_type.page_size)
                    )
                    for i in range(1, 5)
                ]
            )
            # Mask off the page bits of top level page map
            page_table_mask = b"\x00\xf0\xff\xff\xff\xff\xff\xff" * 4
            page_table = data[
                top_pae_page
                - data_offset : top_pae_page
                - data_offset
                + (4 * self.ptr_size)
            ]
            # Compare them
            anded_bytes = self._and_bytes(page_table, page_table_mask)
            if anded_bytes == expected_table:
                return top_pae_page, dtb[1]
            # Return None since the dtb value *isn't* None
            return None
        return dtb


class DtbSelfRef64bitAArch64(DtbSelfReferential):
    def __init__(self) -> None:
        """
        DTB was observed to be masked out with 0x60000000000000 (MiFillSystemPtes references ?),
        but some pointers are also given upper bits masking on physical addresses.
        HalpInterruptBuildGlobalStartupStub() kernel function allocates 0x28 bytes for the DTB.
        """
        super().__init__(
            layer_type=arm.WindowsAArch64,
            ptr_struct="Q",
            mask=(1 << 0x28) - 1 ^ arm.WindowsAArch64.page_mask,
            valid_range=range(0x100, 0x300),
            reserved_bits=0x0,
        )


class PageMapScanner(interfaces.layers.ScannerInterface):
    """Scans through all pages using DTB tests to determine a dtb offset and
    architecture."""

    overlap = 0x4000
    thread_safe = True
    tests = [DtbSelfRef64bit(), DtbSelfRefPae(), DtbSelfRef32bit()]
    """The default tests to run when searching for DTBs"""

    def __init__(self, tests: Optional[List[DtbSelfReferential]]) -> None:
        super().__init__()
        if tests:
            self.tests = tests

    def __call__(
        self, data: bytes, data_offset: int
    ) -> Generator[Tuple[DtbSelfReferential, int], None, None]:
        for page_offset in range(0, len(data), 0x1000):
            for test in self.tests:
                result = test(data, data_offset, page_offset)
                if result is not None:
                    yield (test, result[0])


class WindowsIntelStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 40
    exclusion_list = ["mac", "linux"]

    # Group these by region so we only run over the data once
    test_sets = [
        # FIXME: Trying each architecture might take some (unnecessary) time ?
        # FIXME: AArch64 was set on top, to speed-up tests
        (
            "Detecting Self-referential pointer for AArch64 windows",
            [DtbSelfRef64bitAArch64()],
            # This offset was found by observations between memory samples :
            # 0x800a9000, 0x80d45000, 0x80342800, 0x802a9800
            # It is also referenced in the Windows kernel.
            # TODO: size is arbitrary for now
            [(0x80000000, 0xF00000)],
        ),
        (
            "Detecting Self-referential pointer for recent windows",
            [DtbSelfRef64bit()],
            [(0x150000, 0x150000), (0x650000, 0xA0000)],
        ),
        (
            "Older windows fixed location self-referential pointers",
            [DtbSelfRefPae(), DtbSelfRef32bit(), DtbSelfRef64bitOldWindows()],
            [(0x30000, 0x1000000)],
        ),
    ]

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to determine and stack an intel layer on a physical layer
        where possible.

        Where the DTB scan fails, it attempts a heuristic of checking
        for the DTB within a specific range. New versions of windows,
        with randomized self-referential pointers, appear to always load
        their dtb within a small specific range (`0x1a0000` and
        `0x1b0000`), so instead we scan for all self-referential
        pointers in that range, and ignore any that contain multiple
        self-references (since the DTB is very unlikely to point to
        itself more than once).
        """
        base_layer = context.layers[layer_name]
        if isinstance(base_layer, intel.Intel) or isinstance(base_layer, arm.AArch64):
            return None
        if base_layer.metadata.get("os", None) not in ["Windows", "Unknown"]:
            return None
        layer = config_path = None

        # Check the metadata
        if base_layer.metadata.get("os", None) == "Windows" and base_layer.metadata.get(
            "page_map_offset"
        ):
            arch = base_layer.metadata.get("architecture", None)
            if arch not in ["Intel32", "Intel64"]:
                return None
            # Set the layer type
            layer_type: Type = intel.WindowsIntel
            if arch == "Intel64":
                layer_type = intel.WindowsIntel32e
            elif base_layer.metadata.get("pae", False):
                layer_type = intel.WindowsIntelPAE
            # Construct the layer
            new_layer_name = context.layers.free_layer_name("IntelLayer")
            config_path = interfaces.configuration.path_join(
                "IntelHelper", new_layer_name
            )
            context.config[
                interfaces.configuration.path_join(config_path, "memory_layer")
            ] = layer_name
            context.config[
                interfaces.configuration.path_join(config_path, "page_map_offset")
            ] = base_layer.metadata["page_map_offset"]
            layer = layer_type(
                context,
                config_path=config_path,
                name=new_layer_name,
                metadata={"os": "Windows"},
            )
            page_map_offset = context.config[
                interfaces.configuration.path_join(config_path, "page_map_offset")
            ]
            vollog.debug(f"DTB was given to us by base layer: {hex(page_map_offset)}")
            return layer

        # Self Referential finder
        for description, tests, sections in cls.test_sets:
            vollog.debug(description)
            # There is a very high chance that the DTB will live in these very narrow segments, assuming we couldn't find them previously
            hits: Generator[Tuple[DtbSelfReferential, int], None, None] = (
                base_layer.scan(
                    context,
                    PageMapScanner(tests=tests),
                    sections=sections,
                    progress_callback=progress_callback,
                )
            )

            # Flatten the generator
            def sort_by_tests(x):
                """Key used to sort by tests"""
                return tests.index(x[0]), x[1]

            def get_max_pointer(page_table, test: DtbSelfReferential, ptr_size: int):
                """Determines a pointer from a page_table"""
                max_ptr = 0
                for index in range(0, len(page_table), ptr_size):
                    pointer = struct.unpack(
                        test.ptr_struct, page_table[index : index + ptr_size]
                    )[0]
                    # Mask out unnecessary (upper) bits, as done in DtbSelfReferential
                    # FIXME: prefer test.layer_type.page_mask, but attribute seems broken in Intel layer ("~" ?)
                    pointer &= test.mask ^ (test.layer_type.page_size - 1)
                    # Make sure the pointer is valid, ignore large pages which would require more calculation
                    if pointer & 0x1 and not pointer & test.reserved_bits:
                        max_ptr = max(
                            max_ptr,
                            (pointer ^ (pointer & 0xFFF))
                            % ((1 << test.layer_type._maxvirtaddr) - 1),
                        )
                return max_ptr

            hits = sorted(list(hits), key=sort_by_tests)

            for test, page_map_offset in hits:
                # Turn the page tables into integers and find the largest one
                page_table = base_layer.read(page_map_offset, test.layer_type.page_size)
                ptr_size = struct.calcsize(test.ptr_struct)
                max_pointer = get_max_pointer(page_table, test, ptr_size)

                if max_pointer <= base_layer.maximum_address:
                    vollog.debug(
                        f"{test.__class__.__name__} test succeeded at {hex(page_map_offset)}"
                    )
                    if issubclass(test.layer_type, intel.Intel):
                        new_layer_name = context.layers.free_layer_name("IntelLayer")
                        config_path = interfaces.configuration.path_join(
                            "IntelHelper", new_layer_name
                        )
                        context.config[
                            interfaces.configuration.path_join(
                                config_path, "memory_layer"
                            )
                        ] = layer_name
                        context.config[
                            interfaces.configuration.path_join(
                                config_path, "page_map_offset"
                            )
                        ] = page_map_offset
                        layer = test.layer_type(
                            context,
                            config_path=config_path,
                            name=new_layer_name,
                            metadata={"os": "Windows"},
                        )
                    elif issubclass(test.layer_type, arm.AArch64):
                        cpu_registers = {}
                        # HalpStartupStub() kernel function offsets ttbr1_el1.baddr by 0x800
                        # from ttbr0_el1.baddr
                        page_map_offset += 0x800
                        new_layer_name = context.layers.free_layer_name("AArch64Layer")
                        config_path = interfaces.configuration.path_join(
                            "AArch64Helper", new_layer_name
                        )
                        context.config[
                            interfaces.configuration.path_join(
                                config_path, "memory_layer"
                            )
                        ] = layer_name
                        context.config[
                            interfaces.configuration.path_join(
                                config_path, "page_map_offset"
                            )
                        ] = page_map_offset
                        ttbr1_el1 = arm.set_reg_bits(
                            page_map_offset, arm.AArch64RegMap.TTBR1_EL1.BADDR
                        )
                        tcr_el1 = 0
                        # MmSystemRangeStart = 0xFFFF800000000000 <=> T1SZ = 17
                        tcr_el1 = arm.set_reg_bits(
                            17, arm.AArch64RegMap.TCR_EL1.T1SZ, tcr_el1
                        )
                        tcr_el1 = arm.set_reg_bits(
                            17, arm.AArch64RegMap.TCR_EL1.T0SZ, tcr_el1
                        )
                        # Page size is hardcoded in Windows kernel (CmSiGetPageSize() kernel function)
                        tcr_el1_tg1 = (
                            arm.AArch64RegFieldValues._get_ttbr1_el1_granule_size(
                                4, True
                            )
                        )
                        tcr_el1_tg0 = (
                            arm.AArch64RegFieldValues._get_ttbr0_el1_granule_size(
                                4, True
                            )
                        )
                        tcr_el1 = arm.set_reg_bits(
                            tcr_el1_tg1, arm.AArch64RegMap.TCR_EL1.TG1, tcr_el1
                        )
                        tcr_el1 = arm.set_reg_bits(
                            tcr_el1_tg0, arm.AArch64RegMap.TCR_EL1.TG0, tcr_el1
                        )

                        cpu_registers[arm.AArch64RegMap.TCR_EL1.__name__] = tcr_el1
                        cpu_registers[arm.AArch64RegMap.TTBR1_EL1.__name__] = ttbr1_el1
                        context.config[path_join(config_path, "cpu_registers")] = (
                            json.dumps(cpu_registers)
                        )

                        context.config[path_join(config_path, "entry_format")] = "<Q"

                        layer = test.layer_type(
                            context,
                            config_path=config_path,
                            name=new_layer_name,
                            metadata={"os": "Windows"},
                        )
                    break
                else:
                    vollog.debug(
                        f"Max pointer for hit with test {test.__class__.__name__} not met: {hex(max_pointer)} > {hex(base_layer.maximum_address)}"
                    )
            if layer is not None and config_path:
                break

        if layer is not None and config_path:
            vollog.debug(
                "DTB was found at: 0x{:0x}".format(
                    context.config[
                        interfaces.configuration.path_join(
                            config_path, "page_map_offset"
                        )
                    ]
                )
            )
        return layer


class WinSwapLayers(interfaces.automagic.AutomagicInterface):
    """Class to read swap_layers filenames from single-swap-layers, create the
    layers and populate the single-layers swap_layers."""

    exclusion_list = ["linux", "mac"]

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Finds translation layers that can have swap layers added."""

        path_join = interfaces.configuration.path_join
        self._translation_requirement = self.find_requirements(
            context,
            config_path,
            requirement,
            requirements.TranslationLayerRequirement,
            shortcut=False,
        )
        for trans_sub_config, trans_req in self._translation_requirement:
            if not isinstance(trans_req, requirements.TranslationLayerRequirement):
                # We need this so the type-checker knows we're a TranslationLayerRequirement
                continue
            swap_sub_config, swap_req = self.find_swap_requirement(
                trans_sub_config, trans_req
            )

            counter = 0
            swap_config = interfaces.configuration.parent_path(swap_sub_config)

            if swap_req and swap_req.unsatisfied(context, swap_config):
                # See if any of them need constructing

                for swap_location in self.config.get("single_swap_locations", []):
                    # Setup config locations/paths
                    current_layer_name = swap_req.name + str(counter)
                    current_layer_path = path_join(swap_sub_config, current_layer_name)
                    layer_loc_path = path_join(current_layer_path, "location")
                    layer_class_path = path_join(current_layer_path, "class")
                    counter += 1

                    # Fill in the config
                    if swap_location:
                        context.config[current_layer_path] = current_layer_name
                        try:
                            context.config[layer_loc_path] = (
                                requirements.URIRequirement.location_from_file(
                                    swap_location
                                )
                            )
                        except ValueError:
                            vollog.warning(
                                f"Volatility swap_location {swap_location} could not be validated - swap layer disabled"
                            )
                            continue
                        context.config[layer_class_path] = (
                            "volatility3.framework.layers.physical.FileLayer"
                        )

                    # Add the requirement
                    new_req = requirements.TranslationLayerRequirement(
                        name=current_layer_name,
                        description="Swap Layer",
                        optional=False,
                    )
                    swap_req.add_requirement(new_req)

                context.config[path_join(swap_sub_config, "number_of_elements")] = (
                    counter
                )
                context.config[swap_sub_config] = True

                swap_req.construct(context, swap_config)

    @staticmethod
    def find_swap_requirement(
        config: str, requirement: requirements.TranslationLayerRequirement
    ) -> Tuple[str, Optional[requirements.LayerListRequirement]]:
        """Takes a Translation layer and returns its swap_layer requirement."""
        swap_req = None
        for req_name in requirement.requirements:
            req = requirement.requirements[req_name]
            if (
                isinstance(req, requirements.LayerListRequirement)
                and req.name == "swap_layers"
            ):
                swap_req = req
                continue

        swap_config = interfaces.configuration.path_join(config, "swap_layers")
        return swap_config, swap_req

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns the requirements of this plugin."""
        return [
            requirements.ListRequirement(
                name="single_swap_locations",
                element_type=str,
                min_elements=0,
                max_elements=16,
                description="Specifies a list of swap layer URIs for use with single-location",
                optional=True,
            )
        ]
