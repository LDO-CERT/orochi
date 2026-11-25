from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("website", "0083_value_jsonb_gin_idx"),
    ]

    operations = [
        # Existing services keep the previous behaviour (no TLS verification, e.g. self-signed MISP);
        # services created from now on verify certificates.
        migrations.AddField(
            model_name="service",
            name="verify_ssl",
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name="service",
            name="verify_ssl",
            field=models.BooleanField(
                default=True,
                help_text="Verify the TLS certificate of the service. Disable only for self-hosted instances "
                "with self-signed certificates.",
            ),
        ),
    ]
