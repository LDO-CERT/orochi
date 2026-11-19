# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
# Orochi: volatility3 develop @ 77ff0b1932d7 (automagic/linux.py) merged with the AArch64 support
# of volatilityfoundation/volatility3#1088 (Abyss-W4tcher, head 5ee05ce7b440). Upstream improvements kept:
#   - symbol cache through symbol_cache.load_cache_manager()
#   - Linux specific Intel layers (LinuxIntel, LinuxIntelPAE, LinuxIntel32e: PROT_NONE PTE handling)
#   - 32-bit PAE detection through pkmap_count
#   - init_task sanity check against fragments of the unrelocated kernel ELF
#   - LinuxIntelVMCOREINFOStacker
# Drop this file once #1088 is merged upstream.

import functools
import logging
import struct
from typing import Dict, Optional, Tuple, Union

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.automagic import symbol_cache, symbol_finder
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import path_join
from volatility3.framework.layers import arm, intel, scanners
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)


class LinuxStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 35
    exclusion_list = ["mac", "windows"]

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify linux within this layer."""
        # Bail out by default unless we can stack properly
        layer = context.layers[layer_name]

        # Never stack on top of a linux layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, (intel.Intel, arm.AArch64)):
            return None

        linux_banners = symbol_cache.load_cache_manager().get_identifier_dictionary(
            operating_system="linux"
        )
        # If we have no banners, don't bother scanning
        if not linux_banners:
            vollog.info(
                "No Linux banners found - if this is a linux plugin, please check your symbol files location"
            )
            return None

        seen_banners = set()
        mss = scanners.MultiStringScanner([x for x in linux_banners if x is not None])
        for _, banner in layer.scan(
            context=context, scanner=mss, progress_callback=progress_callback
        ):
            # No need to try stackers on the same banner more than once
            if banner in seen_banners:
                continue
            seen_banners.add(banner)

            vollog.debug(f"Identified banner: {repr(banner)}")

            isf_path = linux_banners.get(banner, None)
            if isf_path:
                table_name = context.symbol_space.free_table_name("LinuxStacker")
                table = linux.LinuxKernelIntermedSymbols(
                    context,
                    "temporary." + table_name,
                    name=table_name,
                    isf_url=isf_path,
                )
                context.symbol_space.append(table)
                new_layer_name = context.layers.free_layer_name("LinuxLayer")
                config_path = path_join("LinuxHelper", new_layer_name)
                context.config[path_join(config_path, "memory_layer")] = layer_name
                context.config[
                    path_join(config_path, LinuxSymbolFinder.banner_config_key)
                ] = str(banner, "latin-1")

                linux_arch_stackers = [LinuxIntelSubStacker, LinuxAArch64SubStacker]
                for linux_arch_stacker in linux_arch_stackers:
                    try:
                        sub_stacker = linux_arch_stacker(cls)
                        layer = sub_stacker.stack(
                            context=context,
                            layer_name=layer_name,
                            table=table,
                            table_name=table_name,
                            config_path=config_path,
                            new_layer_name=new_layer_name,
                            banner=banner,
                            progress_callback=progress_callback,
                        )
                        if layer:
                            vollog.debug(f"Detected {layer.__class__.__name__} layer")
                            return layer
                    except Exception as e:
                        vollog.exception(e)

        vollog.debug("No suitable Linux banner could be matched")
        return None

    @classmethod
    def verify_translation_by_banner(
        cls,
        context: interfaces.context.ContextInterface,
        layer,
        layer_name: str,
        linux_banner_address: int,
        target_banner: bytes,
        logger: logging.Logger = vollog,
    ) -> bool:
        """Determine if a stacked layer is correct or a false positive, by calling the underlying
        _translate method against the linux_banner symbol virtual address. Then, compare it with
        the detected banner to verify the correct translation.
        """

        try:
            banner_phys_address = layer._translate(linux_banner_address)[0]
            banner_value = context.layers[layer_name].read(
                banner_phys_address, len(target_banner)
            )
        except exceptions.InvalidAddressException as e:
            logger.log(
                constants.LOGLEVEL_VVVV,
                f'Unable to translate "linux_banner" symbol virtual address : {e}',
            )
            return False

        if not banner_value == target_banner:
            logger.log(
                constants.LOGLEVEL_VV,
                f"Mismatch between scanned and virtually translated linux banner : {target_banner} != {banner_value}.",
            )
            return False

        return True

    @classmethod
    @functools.lru_cache()
    def find_aslr(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Tuple[int, int]:
        """Determines the offset of the actual DTB in physical space and its
        symbol offset.

        Unlike upstream (Intel only), kaslr_shift is the plain difference between the
        physical and the virtual address of init_task, so that it works for every
        architecture: callers add it to a symbol virtual address to get its physical one.

        Returns:
            kaslr_shift and aslr_shift
        """

        module = context.module(symbol_table, layer_name, 0)
        swapper_signature = rb"swapper(\/0|\x00\x00)\x00\x00\x00\x00\x00\x00"
        address_mask = context.symbol_space[symbol_table].config.get(
            "symbol_mask", None
        )
        init_task_symbol = symbol_table + constants.BANG + "init_task"
        init_task_json_address = context.symbol_space.get_symbol(
            init_task_symbol
        ).address
        task_symbol = module.get_type("task_struct")
        comm_child_offset = task_symbol.relative_child_offset("comm")

        for offset in context.layers[layer_name].scan(
            scanner=scanners.RegExScanner(swapper_signature),
            context=context,
            progress_callback=progress_callback,
        ):
            init_task_address = offset - comm_child_offset
            init_task = module.object(
                object_type="task_struct", offset=init_task_address, absolute=True
            )
            if init_task.pid != 0:
                continue
            elif (
                init_task.has_member("state")
                and init_task.state.cast("unsigned int") != 0
            ):
                continue
            elif init_task.active_mm.cast("long unsigned int") == module.get_symbol(
                "init_mm"
            ).address and init_task.tasks.next.cast(
                "long unsigned int"
            ) == init_task.tasks.prev.cast("long unsigned int"):
                # The idle task steals `mm` from previously running task, i.e.,
                # `init_mm` is only used as long as no CPU has ever been idle.
                # This catches cases where we found a fragment of the
                # unrelocated ELF file instead of the running kernel.
                continue

            # ASLR calculation
            aslr_shift = (
                int.from_bytes(
                    init_task.files.cast("bytes", length=init_task.files.vol.size),
                    byteorder=init_task.files.vol.data_format.byteorder,
                )
                - module.get_symbol("init_files").address
            )
            if address_mask:
                aslr_shift = aslr_shift & address_mask

            # KASLR calculation (physical symbol address - virtual symbol address)
            kaslr_shift = init_task_address - init_task_json_address

            # Check ASLR and KASLR candidates
            if aslr_shift & 0xFFF != 0 or kaslr_shift & 0xFFF != 0:
                continue
            vollog.debug(
                f"Linux addresses shift values determined: KASLR (physical) = {hex(kaslr_shift)}, ASLR (virtual) = {hex(aslr_shift)}"
            )
            return kaslr_shift, aslr_shift

        # We don't throw an exception, because we may legitimately not have an ASLR shift, but we report it
        vollog.debug("Scanners could not determine any ASLR shifts, using 0 for both")
        return 0, 0

    @staticmethod
    def virtual_to_physical_address(addr: int) -> int:
        """Kept for compatibility with upstream LinuxIntelStacker callers."""
        return LinuxIntelSubStacker.virtual_to_physical_address(addr)


# Upstream name of the stacker, for third party code importing it
LinuxIntelStacker = LinuxStacker


class LinuxIntelSubStacker:
    _logger = logging.getLogger(f"{__module__}.{__qualname__}")
    __START_KERNEL_map_x64 = 0xFFFFFFFF80000000
    __START_KERNEL_map_x86 = 0xC0000000

    def __init__(self, parent_stacker: LinuxStacker) -> None:
        self.parent_stacker = parent_stacker

    def stack(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        table: linux.LinuxKernelIntermedSymbols,
        table_name: str,
        config_path: str,
        new_layer_name: str,
        banner: bytes,
        progress_callback: constants.ProgressCallback = None,
    ) -> Union[intel.LinuxIntel, intel.LinuxIntelPAE, intel.LinuxIntel32e, None]:
        if "init_top_pgt" in table.symbols:
            layer_class = intel.LinuxIntel32e
            dtb_symbol_name = "init_top_pgt"
        elif "init_level4_pgt" in table.symbols:
            layer_class = intel.LinuxIntel32e
            dtb_symbol_name = "init_level4_pgt"
        elif "pkmap_count" in table.symbols and table.get_symbol(
            "pkmap_count"
        ).type.count in (512, 2048):
            layer_class = intel.LinuxIntelPAE
            dtb_symbol_name = "swapper_pg_dir"
        else:
            layer_class = intel.LinuxIntel
            dtb_symbol_name = "swapper_pg_dir"

        kaslr_shift, aslr_shift = self.parent_stacker.find_aslr(
            context,
            table_name,
            layer_name,
            progress_callback=progress_callback,
        )
        dtb = table.get_symbol(dtb_symbol_name).address
        dtb = (
            dtb + kaslr_shift
            if kaslr_shift != 0
            else self.virtual_to_physical_address(dtb)
        )

        # Build the new layer
        context.config[path_join(config_path, "page_map_offset")] = dtb
        layer = layer_class(
            context,
            config_path=config_path,
            name=new_layer_name,
            metadata={"os": "Linux"},
        )
        layer.config["kernel_virtual_offset"] = aslr_shift

        # Verify layer by translating the "linux_banner" symbol virtual address
        test_banner_equality = self.parent_stacker.verify_translation_by_banner(
            context=context,
            layer=layer,
            layer_name=layer_name,
            linux_banner_address=table.get_symbol("linux_banner").address + aslr_shift,
            target_banner=banner,
            logger=self._logger,
        )

        if layer and dtb and test_banner_equality:
            self._logger.debug(f"DTB was found at: {hex(dtb)}")
            return layer
        else:
            layer.destroy()

        return None

    @classmethod
    def virtual_to_physical_address(cls, addr: int) -> int:
        """Converts a virtual Intel Linux address to a physical one (does not account
        of ASLR)"""
        # Detect x64/x86 address space
        if addr > cls.__START_KERNEL_map_x64:
            return addr - cls.__START_KERNEL_map_x64
        return addr - cls.__START_KERNEL_map_x86


class LinuxAArch64SubStacker:
    _logger = logging.getLogger(f"{__module__}.{__qualname__}")
    # https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/
    # CPU register, bound to its attribute name in the "cpuinfo_arm64" kernel struct
    _optional_cpu_registers = {
        arm.AArch64RegMap.ID_AA64MMFR1_EL1.__name__: "reg_id_aa64mmfr1"
    }

    def __init__(self, parent_stacker: LinuxStacker) -> None:
        self.parent_stacker = parent_stacker

    def stack(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        table: linux.LinuxKernelIntermedSymbols,
        table_name: str,
        config_path: str,
        new_layer_name: str,
        banner: bytes,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[arm.LinuxAArch64]:
        layer_class = arm.LinuxAArch64
        kaslr_shift, aslr_shift = self.parent_stacker.find_aslr(
            context,
            table_name,
            layer_name,
            progress_callback=progress_callback,
        )
        ttb1 = table.get_symbol("swapper_pg_dir").address + kaslr_shift
        context.config[path_join(config_path, arm.AArch64RegMap.TTBR1_EL1.__name__)] = (
            arm.set_reg_bits(ttb1, arm.AArch64RegMap.TTBR1_EL1.BADDR)
        )
        context.config[path_join(config_path, "page_map_offset")] = ttb1
        entry_format = (
            "<"
            if table.get_type("pointer").vol.data_format.byteorder == "little"
            else ">"
        )
        entry_format += (
            "Q" if table.get_type("pointer").vol.data_format.length == 8 else "I"
        )
        context.config[path_join(config_path, "entry_format")] = entry_format

        # CREDIT : https://github.com/crash-utility/crash/blob/28891d1127542dbb2d5ba16c575e14e741ed73ef/arm64.c#L941
        kernel_flags = 0
        if "_kernel_flags_le" in table.symbols:
            kernel_flags = table.get_symbol("_kernel_flags_le").address
        if "_kernel_flags_le_hi32" in table.symbols:
            kernel_flags |= table.get_symbol("_kernel_flags_le_hi32").address << 32
        if "_kernel_flags_le_lo32" in table.symbols:
            kernel_flags |= table.get_symbol("_kernel_flags_le_lo32").address

        # https://www.kernel.org/doc/Documentation/arm64/booting.txt
        page_size_kernel_space_bit = (kernel_flags >> 1) & 3
        page_size_kernel_space_candidates = (
            [4**page_size_kernel_space_bit]
            if 1 <= page_size_kernel_space_bit <= 3
            else [4, 16, 64]
        )

        # Linux source : v6.7/source/arch/arm64/include/asm/memory.h#L186 - v5.7/source/arch/arm64/include/asm/memory.h#L160
        va_bits = 0
        if "vabits_actual" in table.symbols:
            vabits_actual_phys_addr = (
                table.get_symbol("vabits_actual").address + kaslr_shift
            )
            # Linux source : v6.7/source/arch/arm64/Kconfig#L1263, VA_BITS
            (va_bits,) = struct.unpack(
                entry_format,
                context.layers[layer_name].read(
                    vabits_actual_phys_addr, struct.calcsize(entry_format)
                ),
            )
        if not va_bits:
            # Count leftmost bits equal to 1, deduce number of used bits for virtual addressing.
            # Example :
            #     linux_banner_address = 0xffff800081822f08
            #     va_bits = (linux_banner_address ^ (2**64 - 1)).bit_length() + 1 = 48
            va_bits = (
                table.get_symbol("linux_banner").address ^ (2**64 - 1)
            ).bit_length() + 1

        # Determining the number of useful bits in virtual addresses (VA_BITS)
        # is not straightforward, and not available in the kernel symbols.
        # Calculation by masking works great, but not in every case, due to the AArch64 memory layout,
        # sometimes pushing kernel addresses "too far" from the TTB1 start.
        # See https://www.kernel.org/doc/html/v5.5/arm64/memory.html.
        # Errors are by 1 or 2 bits, so we can safely try va_bits - {1,2,3}.
        va_bits_candidates = [va_bits] + [va_bits + i for i in range(-1, -4, -1)]
        for va_bits in va_bits_candidates:
            # T1SZ is considered equal to T0SZ
            tcr_el1 = 0
            tcr_el1 = arm.set_reg_bits(
                64 - va_bits, arm.AArch64RegMap.TCR_EL1.T1SZ, tcr_el1
            )
            tcr_el1 = arm.set_reg_bits(
                64 - va_bits, arm.AArch64RegMap.TCR_EL1.T0SZ, tcr_el1
            )

            # If "_kernel_flags_le*" aren't in the symbols, we can still do a quick bruteforce on [4,16,64] page sizes
            # False positives cannot happen, as translation indexes will be off on wrong page and va sizes
            for page_size_kernel_space in page_size_kernel_space_candidates:
                # Kernel space page size is considered equal to the user space page size
                tcr_el1_tg1 = arm.AArch64RegFieldValues._get_ttbr1_el1_granule_size(
                    page_size_kernel_space, True
                )
                tcr_el1_tg0 = arm.AArch64RegFieldValues._get_ttbr0_el1_granule_size(
                    page_size_kernel_space, True
                )
                tcr_el1 = arm.set_reg_bits(
                    tcr_el1_tg1, arm.AArch64RegMap.TCR_EL1.TG1, tcr_el1
                )
                tcr_el1 = arm.set_reg_bits(
                    tcr_el1_tg0, arm.AArch64RegMap.TCR_EL1.TG0, tcr_el1
                )
                context.config[
                    path_join(config_path, arm.AArch64RegMap.TCR_EL1.__name__)
                ] = tcr_el1

                # Build layer
                layer = layer_class(
                    context,
                    config_path=config_path,
                    name=new_layer_name,
                    metadata={"os": "Linux"},
                )
                layer.config["kernel_virtual_offset"] = aslr_shift

                test_banner_equality = self.parent_stacker.verify_translation_by_banner(
                    context=context,
                    layer=layer,
                    layer_name=layer_name,
                    linux_banner_address=table.get_symbol("linux_banner").address
                    + aslr_shift,
                    target_banner=banner,
                    logger=self._logger,
                )

                if layer and ttb1 and test_banner_equality:
                    try:
                        optional_cpu_registers = self.get_registers_from_cpuinfo_arm64(
                            context=context,
                            layer_name=layer_name,
                            table_name=table_name,
                            registers=self._optional_cpu_registers,
                            kaslr_shift=kaslr_shift,
                        )
                        layer_req = [req.name for req in layer.get_requirements()]
                        for reg, reg_val in optional_cpu_registers.items():
                            # Verify register's presence in the requirements
                            if reg in layer_req:
                                layer.config[reg] = reg_val
                    except exceptions.SymbolError as e:
                        self._logger.log(constants.LOGLEVEL_VVV, e, exc_info=True)
                    self._logger.debug(f"TTB1 was found at: {hex(ttb1)}")
                    return layer
                else:
                    layer.destroy()

        return None

    @classmethod
    def get_registers_from_cpuinfo_arm64(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        table_name: str,
        registers: Dict[str, str],
        kaslr_shift: int,
    ) -> Dict[str, int]:
        tmp_kernel_module = context.module(table_name, layer_name, kaslr_shift)
        boot_cpu_data_struct = tmp_kernel_module.object_from_symbol("boot_cpu_data")
        results = {}
        for reg, reg_attribute_name in registers.items():
            try:
                cpu_reg_value = getattr(boot_cpu_data_struct, reg_attribute_name)
                results[reg] = cpu_reg_value
            except AttributeError:
                cls._logger.log(
                    constants.LOGLEVEL_VVV,
                    f"boot_cpu_data struct does not include the {reg_attribute_name} field.",
                )

        return results


class LinuxSymbolFinder(symbol_finder.SymbolFinder):
    """Linux symbol loader based on uname signature strings."""

    banner_config_key = "kernel_banner"
    operating_system = "linux"
    symbol_class = "volatility3.framework.symbols.linux.LinuxKernelIntermedSymbols"
    exclusion_list = ["mac", "windows"]

    @classmethod
    def find_aslr(cls, *args):
        return LinuxStacker.find_aslr(*args)[1]


class LinuxIntelVMCOREINFOStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 34
    exclusion_list = ["mac", "windows"]

    @staticmethod
    def _check_versions() -> bool:
        """Verify the versions of the required modules"""
        # Check VMCOREINFO API version
        vmcoreinfo_version_required = (1, 0, 0)
        if not requirements.VersionRequirement.matches_required(
            vmcoreinfo_version_required, linux.VMCoreInfo.version
        ):
            vollog.info(
                "VMCOREINFO version not suitable: required %s found %s",
                vmcoreinfo_version_required,
                linux.VMCoreInfo.version,
            )
            return False

        return True

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify linux within this layer."""

        # Verify the versions of the required modules
        if not cls._check_versions():
            return None

        # Bail out by default unless we can stack properly
        layer = context.layers[layer_name]

        # Never stack on top of a linux layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, (intel.Intel, arm.AArch64)):
            return None

        linux_banners = symbol_cache.load_cache_manager().get_identifier_dictionary(
            operating_system="linux"
        )
        if not linux_banners:
            # If we have no banners, don't bother scanning
            vollog.info(
                "No Linux banners found - if this is a linux plugin, please check your "
                "symbol files location"
            )
            return None

        vmcoreinfo_elf_notes_iter = linux.VMCoreInfo.search_vmcoreinfo_elf_note(
            context=context,
            layer_name=layer_name,
            progress_callback=progress_callback,
        )

        # Iterate through each VMCOREINFO ELF note found, using the first one that is valid.
        for _vmcoreinfo_offset, vmcoreinfo in vmcoreinfo_elf_notes_iter:
            shifts = cls._vmcoreinfo_find_aslr(vmcoreinfo)
            if not shifts:
                # Let's try the next VMCOREINFO, in case this one isn't correct.
                continue

            kaslr_shift, aslr_shift = shifts

            dtb = cls._vmcoreinfo_get_dtb(vmcoreinfo, aslr_shift, kaslr_shift)
            if dtb is None:
                # Discard this VMCOREINFO immediately
                continue

            is_32bit, is_pae = cls._vmcoreinfo_is_32bit(vmcoreinfo)
            if is_32bit:
                layer_class = intel.IntelPAE if is_pae else intel.Intel
            else:
                layer_class = intel.Intel32e

            uts_release = vmcoreinfo["OSRELEASE"]

            # See how linux_banner constant is built in the linux kernel
            linux_version_prefix = f"Linux version {uts_release} (".encode()
            valid_banners = [
                x for x in linux_banners if x and x.startswith(linux_version_prefix)
            ]
            if not valid_banners:
                # There's no banner matching this VMCOREINFO, keep trying with the next one
                continue
            elif len(valid_banners) == 1:
                # Usually, we narrow down the Linux banner list to a single element.
                # Using BytesScanner here is slightly faster than MultiStringScanner.
                scanner = scanners.BytesScanner(valid_banners[0])
            else:
                scanner = scanners.MultiStringScanner(valid_banners)

            join = interfaces.configuration.path_join
            for match in layer.scan(
                context=context, scanner=scanner, progress_callback=progress_callback
            ):
                # Unfortunately, the scanners do not maintain a consistent interface
                banner = match[1] if isinstance(match, Tuple) else valid_banners[0]

                isf_path = linux_banners.get(banner, None)
                if not isf_path:
                    vollog.warning(
                        "Identified banner %r, but no matching ISF is available.",
                        banner,
                    )
                    continue

                vollog.debug("Identified banner: %r", banner)
                table_name = context.symbol_space.free_table_name("LintelStacker")
                table = linux.LinuxKernelIntermedSymbols(
                    context,
                    f"temporary.{table_name}",
                    name=table_name,
                    isf_url=isf_path,
                )
                context.symbol_space.append(table)

                # Build the new layer
                new_layer_name = context.layers.free_layer_name("primary")
                config_path = join("vmcoreinfo", new_layer_name)
                kernel_banner = LinuxSymbolFinder.banner_config_key
                banner_str = banner.decode(encoding="latin-1")
                context.config[join(config_path, kernel_banner)] = banner_str
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[join(config_path, "kernel_virtual_offset")] = aslr_shift
                layer = layer_class(
                    context,
                    config_path=config_path,
                    name=new_layer_name,
                    metadata={"os": "Linux"},
                )

                if layer:
                    vollog.debug(
                        "Values found in VMCOREINFO: KASLR=0x%x, ASLR=0x%x, DTB=0x%x",
                        kaslr_shift,
                        aslr_shift,
                        dtb,
                    )

                    return layer

        vollog.debug("No suitable linux banner could be matched")
        return None

    @staticmethod
    def _vmcoreinfo_find_aslr(vmcoreinfo) -> Tuple[int, int]:
        phys_base = vmcoreinfo.get("NUMBER(phys_base)")
        if phys_base is None:
            # In kernel < 4.10, there may be a SYMBOL(phys_base), but as noted in the
            # c401721ecd1dcb0a428aa5d6832ee05ffbdbffbbe commit comment, this value
            # isn't useful for calculating the physical address.
            # There's nothing we can do here, so let's try with the next VMCOREINFO or
            # the next Stacker.
            return None

        # kernels 3.14 (b6085a865762236bb84934161273cdac6dd11c2d) KERNELOFFSET was added
        kerneloffset = vmcoreinfo.get("KERNELOFFSET")
        if kerneloffset is None:
            # kernels < 3.14 if KERNELOFFSET is missing, KASLR might not be implemented.
            # Oddly, NUMBER(phys_base) is present without it. To be safe, proceed only
            # if both are present.
            return None

        aslr_shift = kerneloffset
        kaslr_shift = phys_base + aslr_shift

        return kaslr_shift, aslr_shift

    @staticmethod
    def _vmcoreinfo_get_dtb(vmcoreinfo, aslr_shift, kaslr_shift) -> int:
        """Returns the page global directory physical address (a.k.a DTB or PGD)"""
        # In x86-64, since kernels 2.5.22 swapper_pg_dir is a macro to the respective pgd.
        # First, in e3ebadd95cb621e2c7436f3d3646447ac9d5c16d to init_level4_pgt, and later
        # in kernels 4.13 in 65ade2f872b474fa8a04c2d397783350326634e6) to init_top_pgt.
        # In x86-32, the pgd is swapper_pg_dir. So, in any case, for VMCOREINFO
        # SYMBOL(swapper_pg_dir) will always have the right value.
        dtb_vaddr = vmcoreinfo.get("SYMBOL(swapper_pg_dir)")
        if dtb_vaddr is None:
            # Abort, it should be present
            return None

        dtb_paddr = (
            LinuxIntelSubStacker.virtual_to_physical_address(dtb_vaddr)
            - aslr_shift
            + kaslr_shift
        )

        return dtb_paddr

    @staticmethod
    def _vmcoreinfo_is_32bit(vmcoreinfo) -> Tuple[bool, bool]:
        """Returns a tuple of booleans with is_32bit and is_pae values"""
        is_pae = vmcoreinfo.get("CONFIG_X86_PAE", "n") == "y"
        if is_pae:
            is_32bit = True
        else:
            # Check the swapper_pg_dir virtual address size
            dtb_vaddr = vmcoreinfo["SYMBOL(swapper_pg_dir)"]
            is_32bit = dtb_vaddr <= 2**32

        return is_32bit, is_pae
