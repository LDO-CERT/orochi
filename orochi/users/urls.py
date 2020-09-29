from django.urls import path

from orochi.users.views import UserDetailView, UserRedirectView

app_name = "users"
urlpatterns = [
    path("~redirect/", view=UserDetailView.as_view(), name="redirect"),
    path("<str:username>/", view=UserRedirectView.as_view(), name="detail"),
]
