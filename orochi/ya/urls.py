from django.urls import path

from orochi.ya import views

app_name = "ya"
urlpatterns = [
    path("upload", views.upload, name="upload"),
    path("detail", views.detail, name="detail"),
]
