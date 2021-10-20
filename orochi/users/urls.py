from django.urls import path

from orochi.users.views import (
    user_plugins_view,
    user_bookmarks_view,
    user_redirect_view,
    user_yara_view,
)

app_name = "users"
urlpatterns = [
    path("~redirect/", view=user_redirect_view, name="redirect"),
    path("<str:username>/plugins/", view=user_plugins_view, name="plugins"),
    path("<str:username>/bookmarks/", view=user_bookmarks_view, name="bookmarks"),
    path("<str:username>/rules/", view=user_yara_view, name="rules"),
]
