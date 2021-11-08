from datetime import datetime
from django import template
from django.forms import CheckboxInput

register = template.Library()


@register.filter(name="is_checkbox")
def is_checkbox(field):
    return field.field.widget.__class__.__name__ == CheckboxInput().__class__.__name__


@register.filter(name="in_list")
def in_list(value, the_list):
    value = str(value)
    return value in the_list.split(",")


@register.filter(name="starts_with")
def starts_with(value, value_with):
    return value.startswith(value_with)


@register.filter(name="epoch")
def epoch(value):
    return datetime.fromtimestamp(value)
