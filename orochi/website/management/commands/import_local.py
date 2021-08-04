import uuid
from pathlib import Path
from django.conf import settings
from django.db import transaction
from django.core.management.base import BaseCommand
from orochi.website.models import Dump, Result, UserPlugin
from django.contrib.auth import get_user_model
from orochi.website.views import index_f_and_f


class Command(BaseCommand):
    help = "Import dump from local storage"

    def add_arguments(self, parser):
        parser.add_argument("--filepath", type=str)
        parser.add_argument("--name", type=str)
        parser.add_argument("--os", type=str)
        parser.add_argument("--author", type=str)

    def handle(self, *args, **options):
        local_path = Path(options["filepath"])
        media_path = Path("{}/{}".format(settings.MEDIA_ROOT, "uploads"))

        uploaded_name = "{}/{}".format(media_path, local_path.name)

        if not local_path.exists():
            self.stdout.write(self.style.ERROR("Path does not exists"))
            return

        if not Path(settings.MEDIA_ROOT) in Path(local_path).parents:
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
            self.stdout.write(
                self.style.ERROR(
                    'Os not valid: options available "Linux", "Windows", "Mac"'
                )
            )
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
                        result=5 if not up.automatic else 0,
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
            transaction.on_commit(lambda: index_f_and_f(dump.pk, author.pk))

        self.stdout.write(
            self.style.SUCCESS(
                "Dump {} created, file at {}!".format(dump.name, dump.upload.path)
            )
        )
