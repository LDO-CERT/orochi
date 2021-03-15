from django.urls import path
from orochi.ya import views

app_name = "ya"
urlpatterns = [
    path("update_rules", views.update_rules, name="update_rules"),
    path("list", views.list_rules, name="list"),
    path("upload", views.upload, name="upload"),
    path("delete", views.delete, name="delete"),
    path("build", views.build, name="build"),
]
