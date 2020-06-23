from django.core.management.base import BaseCommand

import volatility.plugins
from volatility import framework
from volatility.framework import contexts
from orochi.website.models import Plugin


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
        failures = framework.import_files(volatility.plugins, True)
        available_plugins = framework.list_plugins()
        self.stdout.write("Available Plugins: {}".format(", ".join(installed_plugins)))

        for plugin in plugins:
            if plugin.name not in available_plugins:
                plugin.disabled = True
                plugin.save()
                self.stdout.write(
                    self.style.ERROR("Disabled {}, not installed!".format(plugin))
                )

        for plugin in available_plugins:
            if plugin not in installed_plugins:
                if plugin_name.startswith("linux"):
                    plugin = Plugin(name=plugin_name, operating_system=1)
                elif plugin_name.startswith("windows"):
                    plugin = Plugin(name=plugin_name, operating_system=2)
                elif plugin_name.startswith("mac"):
                    plugin = Plugin(name=plugin_name, operating_system=3)
                else:
                    plugin = Plugin(name=plugin_name, operating_system=4)
                plugin.save()
                self.stdout.write(self.style.SUCCESS("Plugin {} added!".format(plugin)))
