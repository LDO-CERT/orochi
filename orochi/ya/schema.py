import contextlib
from pathlib import Path

import elasticsearch
from django.conf import settings
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import RequestError
from elasticsearch_dsl import Search
from luqum.elasticsearch import ElasticsearchQueryBuilder, SchemaAnalyzer
from luqum.exceptions import ParseSyntaxError
from luqum.parser import parser


class RuleIndex:
    def __init__(self):
        self.es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        self.index_name = "rules"
        self.schema = {
            "mappings": {
                "properties": {
                    "path": {"type": "text", "fielddata": True},
                    "ruleset": {"type": "text", "fielddata": True},
                    "description": {
                        "type": "text",
                        "term_vector": "with_positions_offsets",
                    },
                    "rule": {
                        "type": "text",
                        "term_vector": "with_positions_offsets",
                    },
                },
            }
        }
        self.create_index()

    def create_index(self):
        if not self.es_client.indices.exists(index=self.index_name):
            with contextlib.suppress(elasticsearch.exceptions.RequestError):
                self.es_client.indices.create(index=self.index_name, body=self.schema)

    def delete_index(self):
        if self.es_client.indices.exists(index=self.index_name):
            self.es_client.indices.delete(index=self.index_name)

    def add_document(self, rulepath, ruleset, description, rule_id):
        with open(rulepath, "rb") as f:
            doc = {
                "path": Path(rulepath).name,
                "ruleset": ruleset,
                "description": description,
                "rule": f.read().decode("utf8", "replace"),
            }
            self.es_client.index(index=self.index_name, id=rule_id, body=doc)

    def remove_document(self, rule_id):
        self.es_client.delete(index=self.index_name, id=rule_id)

    def search(self, query, sort, start, length):
        schema_analizer = SchemaAnalyzer(self.schema)
        message_es_builder = ElasticsearchQueryBuilder(
            **schema_analizer.query_builder_options(),
            field_options={"*": {"match_type": "multi_match"}},
        )
        try:
            tree = parser.parse(query)
            query = {"query": message_es_builder(tree)}
            s = Search(index=self.index_name).using(self.es_client).sort(sort)
            s = (
                s.update_from_dict(query)[start:length]
                .highlight("path", fragment_size=40)
                .highlight("ruleset", fragment_size=40)
                .highlight("rule", fragment_size=40)
                .highlight("description", fragment_size=40)
            )

            response = s.execute()
            results = []
            for hit in response:
                parts = []
                if hasattr(hit.meta, "highlight"):
                    for key in hit.meta.highlight.__dict__["_d_"].keys():
                        parts.extend(
                            f"<b style='color:red'>{key}:</b> {value}"
                            for value in hit.meta.highlight.__dict__["_d_"][key]
                        )
                results.append(
                    [
                        hit.meta.id,
                        hit.ruleset,
                        hit.description,
                        hit.path,
                        parts[:5],
                    ]
                )
            return results, response.hits.total.value
        except (ParseSyntaxError, RequestError):
            return [], 0
