from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="home"),
    path("create", views.create, name="index_create"),
    # TODO
    # EDIT INDEX
    # RUN PLUGINS
    # NOTIFY END
    # AJAX
    path("plugins", views.plugins, name="plugins"),
    path("analysis", views.analysis, name="analysis"),
]
