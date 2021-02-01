from django.core.management.base import BaseCommand

import volatility3.plugins
from volatility3 import framework
from volatility3.framework import contexts
from orochi.website.models import Plugin, UserPlugin, Dump, Result
from django.contrib.auth import get_user_model


class Command(BaseCommand):
    help = "Sync Volatility Plugins"

    def handle(self, *args, **kwargs):

        plugins = Plugin.objects.all()
        installed_plugins = [x.name for x in plugins]
        if len(plugins) > 0:
            self.stdout.write(
                self.style.SUCCESS(
                    "Plugins in db: {}".format(", ".join(installed_plugins))
                )
            )
        else:
            self.stdout.write(self.style.SUCCESS("No plugins in db"))

        ctx = contexts.Context()
        failures = framework.import_files(volatility3.plugins, True)
        available_plugins = framework.list_plugins()
        self.stdout.write("Available Plugins: {}".format(", ".join(installed_plugins)))

        # If plugin doesn't exists anymore disable it
        for plugin in plugins:
            if plugin.name not in available_plugins:
                plugin.disabled = True
                plugin.save()
                self.stdout.write(
                    self.style.ERROR(
                        "Plugin {} disabled. It is not available anymore!".format(
                            plugin
                        )
                    )
                )

        # Create new plugin, take os from name
        for plugin in available_plugins:
            if plugin not in installed_plugins:
                if plugin.startswith("linux"):
                    plugin = Plugin(name=plugin, operating_system="Linux")
                elif plugin.startswith("windows"):
                    plugin = Plugin(name=plugin, operating_system="Windows")
                elif plugin.startswith("mac"):
                    plugin = Plugin(name=plugin, operating_system="Mac")
                else:
                    plugin = Plugin(name=plugin, operating_system="Other")
                plugin.save()
                self.stdout.write(self.style.SUCCESS("Plugin {} added!".format(plugin)))

                # Add new plugin in old dump
                for dump in Dump.objects.all():
                    if plugin.operating_system in [dump.operating_system, "Other"]:
                        up, created = Result.objects.get_or_create(
                            dump=dump, plugin=plugin
                        )
                        if created:
                            up.result = 5
                            up.save()
                self.stdout.write(
                    self.style.SUCCESS("Plugin {} added to old dumps!".format(plugin))
                )

            else:
                plugin = Plugin.objects.get(name=plugin)

            # Add new plugin to user
            for user in get_user_model().objects.all():
                up, created = UserPlugin.objects.get_or_create(user=user, plugin=plugin)
                if created:
                    self.stdout.write(
                        self.style.SUCCESS(
                            "Plugin {} added to {}!".format(plugin, user)
                        )
                    )
