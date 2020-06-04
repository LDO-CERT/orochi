from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="home"),
    path("create", views.create, name="index_create"),
    path("delete", views.delete, name="index_delete"),
    path("plugins", views.plugins, name="plugins"),
    path("analysis", views.analysis, name="analysis"),
]
