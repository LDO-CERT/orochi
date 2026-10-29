import logging
import os

from django.core.management.base import BaseCommand, CommandError

from orochi.website.tasks import generate_dwarf_isf_task

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run dwarf2json on a Linux/ARM kernel ELF and optional System.map to generate Volatility 3 ISF symbols (Issue #272 / #1554)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--elf",
            type=str,
            required=True,
            help="Path to the kernel vmlinux ELF binary with DWARF debugging info.",
        )
        parser.add_argument(
            "--system-map",
            type=str,
            default=None,
            help="Optional path to the kernel System.map symbol table.",
        )
        parser.add_argument(
            "--output-name",
            type=str,
            default=None,
            help="Optional filename for the output ISF file (default: added_<elf_stem>.json.xz).",
        )
        parser.add_argument(
            "--dump-pk",
            type=int,
            default=None,
            help="Optional Dump primary key to link and evaluate upon completion.",
        )
        parser.add_argument(
            "--async",
            action="store_true",
            dest="run_async",
            help="Enqueue the dwarf2json compilation task to Dask worker queue.",
        )

    def handle(self, *args, **options):
        elf_path = options["elf"]
        system_map = options.get("system_map")
        output_name = options.get("output_name")
        dump_pk = options.get("dump_pk")
        run_async = options.get("run_async", False)

        if not os.path.exists(elf_path):
            raise CommandError(f"Kernel ELF file not found: {elf_path}")

        if system_map and not os.path.exists(system_map):
            raise CommandError(f"System.map file not found: {system_map}")

        self.stdout.write(self.style.MIGRATE_HEADING(f"Running dwarf2json for ELF: {elf_path}"))
        if system_map:
            self.stdout.write(f"Using System.map: {system_map}")

        if run_async:
            task_res = generate_dwarf_isf_task.enqueue(
                elf_path=elf_path,
                system_map_path=system_map,
                output_name=output_name,
                dump_pk=dump_pk,
            )
            self.stdout.write(self.style.SUCCESS(f"Task successfully enqueued to Dask worker (ID: {task_res.id})"))
            return

        # Synchronous execution
        from orochi.utils.download_symbols import Downloader
        from orochi.website.symbols_assistant import distribute_symbols_to_workers, refresh_symbols

        downloader = Downloader()
        try:
            out_file = downloader.process_raw_kernel(
                elf_path=elf_path,
                system_map_path=system_map,
                output_name=output_name,
            )
            self.stdout.write(self.style.SUCCESS(f"Successfully generated ISF symbol: {out_file}"))
            refresh_symbols()
            dist_res = distribute_symbols_to_workers()
            self.stdout.write(self.style.SUCCESS(f"Symbols synchronized to {dist_res.get('worker_count', 0)} workers."))

            if dump_pk:
                from orochi.utils.volatility_dask_elk import check_runnable
                from orochi.website.defaults import (
                    DUMP_STATUS_COMPLETED,
                    RESULT_STATUS_DISABLED,
                    RESULT_STATUS_NOT_STARTED,
                    SymbolStatus,
                )
                from orochi.website.models import Dump

                dump = Dump.objects.filter(pk=dump_pk).first()
                if dump and check_runnable(dump.pk, dump.operating_system, dump.banner):
                    dump.symbol_status = SymbolStatus.OK
                    dump.status = DUMP_STATUS_COMPLETED
                    dump.result_set.filter(result=RESULT_STATUS_DISABLED).update(result=RESULT_STATUS_NOT_STARTED)
                    dump.save(update_fields=["symbol_status", "status"])
                    self.stdout.write(
                        self.style.SUCCESS(f"Dump {dump.name} ({dump.index}) verified and marked COMPLETED!")
                    )

        except Exception as exc:
            raise CommandError(f"dwarf2json failed: {exc}") from exc
