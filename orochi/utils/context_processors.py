from django.conf import settings


def settings_context(_request):
    """Expose Django settings to templates as ``settings``."""
    return {"settings": settings}
