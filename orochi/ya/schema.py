import luqum
from luqum.parser import parser
from luqum.elasticsearch import SchemaAnalyzer, ElasticsearchQueryBuilder
from luqum.exceptions import ParseSyntaxError
from luqum.tree import SearchField, OrOperation, Group
from django.conf import settings
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from pathlib import Path


class BareTextTransformer(luqum.utils.LuceneTreeTransformer):
    """Convert bare Words to full text search

    In cases where a query string has bare text (no field
    association, we want to construct a DSL query that includes
    all fields in an OR configuration to perform the full
    text search against all fields.

    This class can walk the tree and convert bare Word
    nodes into the required set of SearchField objects.
    """

    def __init__(
        self,
        fields=["path", "description", "ruleset", "rule"],
    ):
        """Create a new BareTextTransformer

        Parameters
        ----------
        fields: list of str
            This is the list of fields that will used to
            create the composite SearchField objects that
            will be OR'ed together to simulate full text
            search.
        """
        super()
        self.fields = fields

    def visit_word(self, node, parent):
        if len(parent) > 0:
            if isinstance(parent[-1], luqum.tree.SearchField):
                return node
        else:
            search_list = [SearchField(f, node) for f in self.fields]
            return Group(OrOperation(*search_list))


class RuleIndex:
    def __init__(self):
        self.es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        self.index_name = "rules"
        self.schema = {
            "mappings": {
                "properties": {
                    "path": {"type": "text"},
                    "ruleset": {"type": "text"},
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

    def add_document(self, rulepath, ruleset, description, rule_id):
        with open(rulepath, "rb") as f:
            doc = {
                "path": Path(rulepath).name,
                "ruleset": ruleset,
                "description": description,
                "rule": f.read().decode("utf8", "replace"),
            }
            res = self.es_client.index(index=self.index_name, id=rule_id, body=doc)

    def remove_document(self, rule_id):
        self.es_client.delete(index=self.index_name, id=rule_id)

    def search(self, query, sort, start, length):
        schema_analizer = SchemaAnalyzer(self.schema)
        message_es_builder = ElasticsearchQueryBuilder(
            **schema_analizer.query_builder_options()
        )
        try:
            tree = parser.parse(query)
            transformer = BareTextTransformer()
            tree = transformer.visit(tree)
            query = {"query": message_es_builder(tree)}

            s = Search(index=self.index_name).using(self.es_client)  # .sort(sort)
            s = (
                s.update_from_dict(query)[start:length]
                .highlight("path", fragment_size=40)
                .highlight("ruleset", fragment_size=40)
                .highlight("rule", fragment_size=40)
                .highlight("description", fragment_size=40)
            )

            response = s.execute()
            return [
                [
                    hit.meta.id,
                    hit.ruleset,
                    hit.description,
                    hit.path,
                    [
                        item
                        for sublist in [
                            hit.meta.highlight.__dict__["_d_"][y]
                            for y in [
                                x for x in hit.meta.highlight.__dict__["_d_"].keys()
                            ]
                        ]
                        for item in sublist
                    ][:5],
                ]
                for hit in response
            ], response.hits.total.value
        except (ParseSyntaxError, AttributeError):
            return [], 0
