from django.db import migrations, models


def init_roles_and_plugin_defaults(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    Plugin = apps.get_model("website", "Plugin")

    # Ensure default groups exist
    for role_name in ["Admin", "Analyst", "Reviewer", "ReadOnly"]:
        Group.objects.get_or_create(name=role_name)

    # Set Admin min_role for heavyweight/memory dumping plugins
    admin_plugins = [
        "windows.dumpfiles.DumpFiles",
        "windows.memmap.Memmap",
        "linux.dumpfiles.DumpFiles",
        "mac.dumpfiles.DumpFiles",
        "windows.vadyarascan.VadYaraScan",
    ]
    Plugin.objects.filter(name__in=admin_plugins).update(min_role="Admin")

    # Set Reviewer min_role for safe info plugins
    reviewer_plugins = [
        "windows.info.Info",
        "linux.banner.Banner",
        "mac.info.Info",
    ]
    Plugin.objects.filter(name__in=reviewer_plugins).update(min_role="Reviewer")


class Migration(migrations.Migration):

    dependencies = [
        ("website", "0075_dump_risk_score_dumpsecret_triagefinding"),
    ]

    operations = [
        migrations.AddField(
            model_name="plugin",
            name="min_role",
            field=models.CharField(
                choices=[
                    ("Admin", "Admin"),
                    ("Analyst", "Analyst"),
                    ("Reviewer", "Reviewer"),
                    ("ReadOnly", "ReadOnly"),
                ],
                default="Analyst",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="userplugin",
            name="can_execute",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Override execution permission (None = follow role, True = allow, False = deny)",
                null=True,
            ),
        ),
        migrations.RunPython(init_roles_and_plugin_defaults, reverse_code=migrations.RunPython.noop),
    ]
