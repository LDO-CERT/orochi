import volatility3.plugins
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from volatility3 import framework
from volatility3.framework import contexts

from orochi.website.defaults import RESULT_STATUS_NOT_STARTED
from orochi.website.models import Dump, Plugin, Result, UserPlugin


class Command(BaseCommand):
    help = "Sync Volatility Plugins"

    def handle(self, *args, **kwargs):
        plugins = Plugin.objects.all()
        installed_plugins = {x.name for x in plugins}
        if plugins:
            self.stdout.write(
                self.style.SUCCESS(f'Plugins in db: {", ".join(installed_plugins)}')
            )
        else:
            self.stdout.write(self.style.SUCCESS("No plugins in db"))

        _ = contexts.Context()
        _ = framework.import_files(volatility3.plugins, True)
        available_plugins = {
            x: y
            for x, y in framework.list_plugins().items()
            if not x.startswith("volatility3.cli.")
        }
        self.stdout.write(f'Available Plugins: {", ".join(available_plugins)}')

        # Disable plugins that are no longer available
        for plugin in plugins:
            if plugin.name not in available_plugins:
                plugin.disabled = True
                plugin.save()
                self.stdout.write(
                    self.style.ERROR(
                        f"Plugin {plugin} disabled. It is not available anymore!"
                    )
                )

        # Create new plugins and update existing ones
        for plugin_name, plugin_class in available_plugins.items():
            if plugin_name not in installed_plugins:
                operating_system = "Other"
                if plugin_name.startswith("linux"):
                    operating_system = "Linux"
                elif plugin_name.startswith("windows"):
                    operating_system = "Windows"
                elif plugin_name.startswith("mac"):
                    operating_system = "Mac"

                plugin = Plugin(
                    name=plugin_name,
                    operating_system=operating_system,
                    comment=plugin_class.__doc__,
                )
                plugin.save()
                self.stdout.write(self.style.SUCCESS(f"Plugin {plugin} added!"))

                # Add new plugin to old dumps
                for dump in Dump.objects.filter(
                    operating_system__in=[operating_system, "Other"]
                ):
                    result, created = Result.objects.get_or_create(
                        dump=dump, plugin=plugin
                    )
                    if created:
                        result.result = RESULT_STATUS_NOT_STARTED
                        result.save()
                self.stdout.write(
                    self.style.SUCCESS(f"Plugin {plugin} added to old dumps!")
                )

            else:
                plugin = Plugin.objects.get(name=plugin_name)
                if not plugin.comment:
                    plugin.comment = plugin_class.__doc__
                    plugin.save()

            # Add new plugin to users
            for user in get_user_model().objects.all():
                _, created = UserPlugin.objects.get_or_create(user=user, plugin=plugin)
                if created:
                    self.stdout.write(
                        self.style.SUCCESS(f"Plugin {plugin} added to {user}!")
                    )
