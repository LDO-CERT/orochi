import logging
import os

from django.core.management.base import BaseCommand, CommandError

from orochi.website.tasks import generate_btf_isf_task

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run btf2json on a Linux BTF file (or stripped vmlinux), System.map, and optional banner to generate Volatility 3 ISF symbols"

    def add_arguments(self, parser):
        parser.add_argument(
            "--btf",
            type=str,
            required=True,
            help="Path to the BTF file (e.g. /sys/kernel/btf/vmlinux) or stripped kernel vmlinux image.",
        )
        parser.add_argument(
            "--system-map",
            type=str,
            default=None,
            help="Optional path to the kernel System.map symbol table.",
        )
        parser.add_argument(
            "--banner",
            type=str,
            default=None,
            help="Optional Linux kernel banner string (required when using a raw BTF file without embedded banner).",
        )
        parser.add_argument(
            "--output-name",
            type=str,
            default=None,
            help="Optional filename for the output ISF file (default: added_btf_<btf_stem>.json.xz).",
        )
        parser.add_argument(
            "--dump-pk",
            type=int,
            default=None,
            help="Optional Dump primary key to link, auto-fill banner if omitted, and evaluate upon completion.",
        )
        parser.add_argument(
            "--async",
            action="store_true",
            dest="run_async",
            help="Enqueue the btf2json compilation task to Dask worker queue.",
        )

    def handle(self, *args, **options):
        btf_path = options["btf"]
        system_map = options.get("system_map")
        banner = options.get("banner")
        output_name = options.get("output_name")
        dump_pk = options.get("dump_pk")
        run_async = options.get("run_async", False)

        if not os.path.exists(btf_path):
            raise CommandError(f"BTF file not found: {btf_path}")

        if system_map and not os.path.exists(system_map):
            raise CommandError(f"System.map file not found: {system_map}")

        self.stdout.write(self.style.MIGRATE_HEADING(f"Running btf2json for BTF: {btf_path}"))
        if system_map:
            self.stdout.write(f"Using System.map: {system_map}")
        if banner:
            self.stdout.write(f"Using banner: {banner}")

        if run_async:
            task_res = generate_btf_isf_task.enqueue(
                btf_path=btf_path,
                system_map_path=system_map,
                banner=banner,
                output_name=output_name,
                dump_pk=dump_pk,
            )
            self.stdout.write(self.style.SUCCESS(f"Task successfully enqueued to Dask worker (ID: {task_res.id})"))
            return

        # Synchronous execution
        from orochi.utils.download_symbols import Downloader
        from orochi.website.models import Dump
        from orochi.website.symbols_assistant import distribute_symbols_to_workers, refresh_symbols

        dump = Dump.objects.filter(pk=dump_pk).first() if dump_pk else None
        effective_banner = banner or (dump.banner.strip("\"' ") if dump and dump.banner else None)

        downloader = Downloader()
        try:
            out_file = downloader.process_btf_kernel(
                btf_path=btf_path,
                system_map_path=system_map,
                banner=effective_banner,
                output_name=output_name,
            )
            self.stdout.write(self.style.SUCCESS(f"Successfully generated BTF ISF symbol: {out_file}"))
            refresh_symbols()
            dist_res = distribute_symbols_to_workers()
            self.stdout.write(self.style.SUCCESS(f"Symbols synchronized to {dist_res.get('worker_count', 0)} workers."))

            if dump:
                from orochi.utils.volatility_dask_elk import check_runnable
                from orochi.website.defaults import (
                    DUMP_STATUS_COMPLETED,
                    RESULT_STATUS_DISABLED,
                    RESULT_STATUS_NOT_STARTED,
                    SymbolStatus,
                )

                if check_runnable(dump.pk, dump.operating_system, dump.banner):
                    dump.symbol_status = SymbolStatus.OK
                    dump.status = DUMP_STATUS_COMPLETED
                    dump.result_set.filter(result=RESULT_STATUS_DISABLED).update(result=RESULT_STATUS_NOT_STARTED)
                    dump.save(update_fields=["symbol_status", "status"])
                    self.stdout.write(
                        self.style.SUCCESS(f"Dump {dump.name} ({dump.index}) verified and marked COMPLETED!")
                    )

        except Exception as exc:
            raise CommandError(f"btf2json failed: {exc}") from exc
