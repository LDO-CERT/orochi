from django.db import models
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from orochi.ya.schema import RuleIndex


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
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE, related_name="rules")

    def __str__(self):
        return "[{}] {}".format(self.ruleset.name, self.path)


@receiver(post_save, sender=Rule)
def add_document(sender, instance, created, **kwargs):
    """Add rule object to elastic"""
    rule_index = RuleIndex()
    rule_index.add_document(
        rulepath=instance.path,
        ruleset=instance.ruleset.name,
        description=instance.ruleset.description,
        rule_id=instance.pk,
    )


@receiver(post_delete, sender=Rule)
def del_document(sender, instance, **kwargs):
    """Remove rule object from elastic"""
    rule_index = RuleIndex()
    rule_index.remove_document(instance.pk)
