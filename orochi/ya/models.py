from django.db import models
from django.contrib.auth import get_user_model


class Ruleset(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    deleted = models.DateTimeField(null=True, blank=True)
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
    deleted = models.DateTimeField(null=True, blank=True)
    path = models.CharField(max_length=255)
    enabled = models.BooleanField(default=True)
    compiled = models.BooleanField(default=False)
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE, related_name="rules")

    def __str__(self):
        return "[{}] {}".format(self.ruleset.name, self.path)
