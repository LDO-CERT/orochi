from django.urls import path

from . import views

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
    path("enable_plugin", views.enable_plugin, name="enable_plugin"),
    path("update_plugins", views.update_plugins, name="update_plugins"),
    path("update_symbols", views.update_symbols, name="update_symbols"),
]
