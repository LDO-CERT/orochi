import os

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search

from orochi.website.defaults import RESULT_STATUS_ERROR, RESULT_STATUS_SUCCESS
from orochi.website.models import Result, Value
from orochi.ya.models import Rule

es_client = Elasticsearch([os.environ["ELASTICSEARCH_URL"]])

rules = Rule.objects.filter(rule__isnull=True)
for rule in rules:
    try:
        with open(rule.path, "rb") as f:
            rule.rule = f.read().decode("utf8", "replace")[:65000]
            rule.save()
    except Exception as e:
        print(e)


results = Result.objects.filter(result__in=[RESULT_STATUS_SUCCESS, RESULT_STATUS_ERROR])
for result in results:
    if values := Value.objects.filter(result=result):
        continue
    s = Search(
        using=es_client, index=f"{result.dump.index}_{result.plugin.name.lower()}"
    )
    vals = s.execute()
    info = [hit.to_dict() for hit in vals if hit.meta.index.split("_")[0] != ".kibana"]
    values = []
    for item in info:
        tmp = {
            k: v
            for k, v in item.items()
            if k
            not in [
                "orochi_createdAt",
                "orochi_os",
                "orochi_plugin",
                "down_path",
            ]
        }
        values.append(Value(result=result, value=tmp))
    Value.objects.bulk_create(values)
