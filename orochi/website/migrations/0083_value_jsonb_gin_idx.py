import django.contrib.postgres.indexes
from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations


class Migration(migrations.Migration):
    # website_value can hold tens of millions of rows: build the index without locking writes.
    atomic = False

    dependencies = [
        ("website", "0082_ctf_models_service_choices"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="value",
            index=django.contrib.postgres.indexes.GinIndex(fields=["value"], name="value_jsonb_gin_idx"),
        ),
    ]
