from operator import itemgetter

from django.urls import reverse
from extra_settings.models import Setting
from guardian.shortcuts import get_objects_for_user

from orochi.website.defaults import (
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    TOAST_RESULT_COLORS,
)
from orochi.website.models import Bookmark


class UpdatesMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_template_response(self, request, response):
        if (
            request.user
            and request.user.is_authenticated
            and response.context_data
            # AVOID RUNNING IN ADMIN COMMANDS
            and not request.path.startswith(reverse("admin:index"))
        ):
            news = []

            dumps = get_objects_for_user(request.user, "website.can_see")
            for dump in dumps:
                news.extend(
                    {
                        "date": result.updated_at,
                        "text": f"Plugin <b>{result.plugin.name}</b> on dump <b>{dump.name}</b> ended<br>"
                        f"Status: <b style='color:{TOAST_RESULT_COLORS[result.result]}'>{result.get_result_display()}</b>",
                    }
                    for result in dump.result_set.exclude(
                        result__in=[
                            RESULT_STATUS_NOT_STARTED,
                            RESULT_STATUS_RUNNING,
                            RESULT_STATUS_DISABLED,
                        ]
                    ).select_related("plugin")
                )
            news = sorted(news, key=itemgetter("date"), reverse=True)
            response.context_data["news"] = news
            bookmarks = Bookmark.objects.filter(user=request.user, star=True)
            response.context_data["bookmarks"] = bookmarks

        # Default logo or pick new one from extra settings
        if logo := Setting.get("CUSTOM_LOGO"):
            response.context_data["logo"] = logo.url
        else:
            response.context_data["logo"] = "/static/images/logo.png"
        return response
