from django.apps import AppConfig


class WebsiteConfig(AppConfig):
    name = "orochi.website"

    def ready(self):
        import orochi.website.signals
