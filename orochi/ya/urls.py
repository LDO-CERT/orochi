from django.urls import path
from orochi.ya import views

app_name = "ya"
urlpatterns = [
    path("update_rules", views.update_rules, name="update_rules"),
    path(
        "generate_default_rule",
        views.generate_default_rule,
        name="generate_default_rule",
    ),
    path("list", views.list_rules, name="list"),
    path("upload", views.upload, name="upload"),
    path("delete", views.delete, name="delete"),
    path("build", views.build, name="build"),
    path("detail", views.detail, name="detail"),
    path("download_rule/<int:pk>", views.download_rule, name="download_rule"),
]
