# Generated by Django 3.1.3 on 2020-11-06 16:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('website', '0024_auto_20200930_1428'),
    ]

    operations = [
        migrations.AddField(
            model_name='dump',
            name='banner',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]
