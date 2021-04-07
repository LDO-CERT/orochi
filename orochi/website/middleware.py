from django.urls import reverse
from operator import itemgetter
from guardian.shortcuts import get_objects_for_user
from orochi.website.models import Bookmark


class UpdatesMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

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
                for result in dump.result_set.exclude(result__in=[0, 5]).select_related(
                    "plugin"
                ):
                    news.append(
                        {
                            "date": result.updated_at,
                            "text": "Plugin <b>{}</b> on dump <b>{}</b> ended<br>Status: <b style='color:{}'>{}</b>".format(
                                result.plugin.name,
                                dump.name,
                                colors[result.result],
                                result.get_result_display(),
                            ),
                        }
                    )
            news = sorted(news, key=itemgetter("date"), reverse=True)
            response.context_data["news"] = news
            bookmarks = Bookmark.objects.filter(user=request.user, star=True)
            response.context_data["bookmarks"] = bookmarks
        return response
