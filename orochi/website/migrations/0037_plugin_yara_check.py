# Generated by Django 3.1.6 on 2021-03-15 19:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("website", "0036_customrule_default"),
    ]

    operations = [
        migrations.AddField(
            model_name="plugin",
            name="yara_check",
            field=models.BooleanField(default=False),
        ),
    ]
