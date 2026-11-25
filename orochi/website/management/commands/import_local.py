import uuid
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from orochi.backends.dask_client import submit_and_confirm
from orochi.utils.volatility_dask_elk import manage_upload
from orochi.website.defaults import RESULT_STATUS_NOT_STARTED, RESULT_STATUS_RUNNING
from orochi.website.models import Dump, Result, UserPlugin


class Command(BaseCommand):
    """Import a memory dump from a local path (``--filepath --name --os --author``, optional ``--password``)."""

    help = "Import dump from local storage"

    def add_arguments(self, parser):
        """Declare path, name, OS, author and archive password options."""
        parser.add_argument("--filepath", type=str)
        parser.add_argument("--name", type=str)
        parser.add_argument("--os", type=str)
        parser.add_argument("--author", type=str)
        parser.add_argument("--password", nargs="?", type=str)

    def handle(self, *args, **options):
        """Copy the file into the uploads folder, create the Dump and start its processing."""
        local_path = Path(options["filepath"])
        media_path = Path(f"{settings.MEDIA_ROOT}/uploads")

        uploaded_name = f"{media_path}/{local_path.name}"

        if not local_path.exists():
            self.stdout.write(self.style.ERROR("Path does not exists"))
            return

        if Path(settings.MEDIA_ROOT) not in Path(local_path).parents:
            self.stdout.write(self.style.ERROR("Path not valid"))
            return

        # IF ALREADY UNDER RIGHT FOLDER OK, ELSE MOVE IT
        if local_path.parent.absolute() == media_path:
            self.stdout.write("File in correct path")
            uploaded_name = local_path
        else:
            local_path.rename(uploaded_name)
            self.stdout.write("File moved to upload folder")

        operating_system = options["os"]
        operating_system = operating_system.capitalize()
        if operating_system not in ["Linux", "Windows", "Mac"]:
            self.stdout.write(self.style.ERROR('Os not valid: options available "Linux", "Windows", "Mac"'))
            return

        name = options["name"]
        author = get_user_model().objects.get(username=options["author"])

        with transaction.atomic():
            dump = Dump(
                author=author,
                index=str(uuid.uuid1()),
                name=name,
                operating_system=operating_system,
            )
            dump.upload.name = str(uploaded_name)
            dump.save()
            Result.objects.bulk_create(
                [
                    Result(
                        plugin=up.plugin,
                        dump=dump,
                        result=(RESULT_STATUS_RUNNING if up.automatic else RESULT_STATUS_NOT_STARTED),
                    )
                    for up in UserPlugin.objects.filter(
                        plugin__operating_system__in=[
                            operating_system,
                            "Other",
                        ],
                        user=author,
                        plugin__disabled=False,
                    )
                ]
            )

        # Submit after the commit and wait until the scheduler holds the task: this process exits right after,
        # and a fire-and-forget submission still in the client's send queue would be lost.
        submit_and_confirm(manage_upload, dump.pk, author.pk, options["password"], None, True)

        self.stdout.write(self.style.SUCCESS(f"Dump {dump.name} created, file at {dump.upload.path}!"))
