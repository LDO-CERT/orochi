from django.contrib.auth import get_user_model
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.db import models


class Ruleset(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    cloned = models.BooleanField(default=False)
    name = models.CharField(max_length=255, unique=True)
    url = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(default=True)
    user = models.ForeignKey(
        get_user_model(), on_delete=models.CASCADE, blank=True, null=True
    )

    @property
    def count_rules(self):
        return self.rules.count()

    def __str__(self):
        return self.name


class Rule(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    path = models.CharField(max_length=255)
    enabled = models.BooleanField(default=True)
    compiled = models.BooleanField(default=False)
    rule = models.TextField(blank=True, null=True)
    error = models.TextField(blank=True, null=True)
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE, related_name="rules")
    search_vector = models.GeneratedField(
        expression=SearchVector("rule", config="english")
        + SearchVector("path", config="english"),
        output_field=SearchVectorField(),
        db_persist=True,
    )

    def __str__(self):
        return f"[{self.ruleset.name}] {self.path}"
