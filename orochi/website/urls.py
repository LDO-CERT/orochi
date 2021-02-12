from django.urls import path, register_converter
from orochi.website import views
from uuid import UUID


class MultiindexConverter:
    regex = "[0-9a-f,-]{36,}"

    def valid_uuid(self, uuid):
        try:
            return UUID(uuid).version
        except ValueError:
            return None

    def to_python(self, value):
        return [x.strip() for x in value.split(",") if self.valid_uuid(x) != None]

    def to_url(self, value):
        return value


class QueryConverter:
    regex = ".*"

    def to_python(self, value):
        return value

    def to_url(self, value):
        return value


register_converter(MultiindexConverter, "idxs")
register_converter(QueryConverter, "query")


app_name = "website"
urlpatterns = [
    path("", views.index, name="home"),
    path(
        "indexes/<idxs:indexes>/plugin/<str:plugin>/query/<query:query>",
        views.bookmarks,
        name="bookmarks",
    ),
    path(
        "indexes/<idxs:indexes>/plugin/<str:plugin>",
        views.bookmarks,
        name="bookmarks",
    ),
    path("create", views.create, name="index_create"),
    path("edit", views.edit, name="index_edit"),
    path("delete", views.delete, name="index_delete"),
    path("plugins", views.plugins, name="plugins"),
    path("analysis", views.analysis, name="analysis"),
    path("plugin", views.plugin, name="plugin"),
    path("parameters", views.parameters, name="parameters"),
    path("symbols", views.symbols, name="symbols"),
    # CHANGELOG
    path("changelog", views.changelog, name="changelog"),
    # EXTERNAL VIEW
    path("json_view/<int:pk>", views.json_view, name="json_view"),
    path(
        "diff_view/<str:index_a>/<str:index_b>/<str:plugin>",
        views.diff_view,
        name="diff_view",
    ),
    # USER PAGE
    path("enable_plugin", views.enable_plugin, name="enable_plugin"),
    path("star_bookmark", views.star_bookmark, name="star_bookmark"),
    path("delete_bookmark", views.delete_bookmark, name="delete_bookmark"),
    path("edit_bookmark", views.edit_bookmark, name="edit_bookmark"),
    # ADMIN
    path("update_plugins", views.update_plugins, name="update_plugins"),
    path("update_symbols", views.update_symbols, name="update_symbols"),
]
