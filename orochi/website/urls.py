from django.urls import path
from orochi.website import views

app_name = "website"
urlpatterns = [
    path("", views.index, name="home"),
    path("create", views.create, name="index_create"),
    path("edit", views.edit, name="index_edit"),
    path("delete", views.delete, name="index_delete"),
    path("plugins", views.plugins, name="plugins"),
    path("analysis", views.analysis, name="analysis"),
    path("plugin", views.plugin, name="plugin"),
    path("parameters", views.parameters, name="parameters"),
    # CHANGELOG
    path("changelog", views.changelog, name="changelog"),
    # EXTERNAL VIEW
    path("json_view/<int:pk>", views.json_view, name="json_view"),
    path(
        "diff_view/<str:index_a>/<str:index_b>/<str:plugin>",
        views.diff_view,
        name="diff_view",
    ),
    # ADMIN
    path("enable_plugin", views.enable_plugin, name="enable_plugin"),
    path("update_plugins", views.update_plugins, name="update_plugins"),
    path("update_symbols", views.update_symbols, name="update_symbols"),
]
