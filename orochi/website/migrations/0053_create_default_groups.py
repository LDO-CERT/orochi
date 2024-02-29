from django.apps import apps
from django.db import migrations


def create_groups(app, schema_editor):
    Group = apps.get_model("auth", "Group")
    group = Group(name="ReadOnly")
    group.save()


class Migration(migrations.Migration):
    dependencies = [("website", "0052_create_superuser")]

    operations = [migrations.RunPython(create_groups)]
