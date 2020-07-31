from django.urls import path

from orochi.users.views import (
    user_detail_view,
    user_redirect_view,
)

app_name = "users"
urlpatterns = [
    path("~redirect/", view=user_redirect_view, name="redirect"),
    path("<str:username>/", view=user_detail_view, name="detail"),
]
