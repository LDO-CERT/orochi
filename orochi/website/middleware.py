from operator import itemgetter

from django.urls import reverse
from guardian.shortcuts import get_objects_for_user

from orochi.website.models import (
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_RUNNING,
    Bookmark,
)


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

            colors = {1: "green", 2: "green", 3: "orange", 4: "red"}

            dumps = get_objects_for_user(request.user, "website.can_see")
            for dump in dumps:
                news.extend(
                    {
                        "date": result.updated_at,
                        "text": f"Plugin <b>{result.plugin.name}</b> on dump <b>{dump.name}</b> ended<br>"
                        f"Status: <b style='color:{colors[result.result]}'>{result.get_result_display()}</b>",
                    }
                    for result in dump.result_set.exclude(
                        result__in=[RESULT_STATUS_RUNNING, RESULT_STATUS_DISABLED]
                    ).select_related("plugin")
                )
            news = sorted(news, key=itemgetter("date"), reverse=True)
            response.context_data["news"] = news
            bookmarks = Bookmark.objects.filter(user=request.user, star=True)
            response.context_data["bookmarks"] = bookmarks
        return response
