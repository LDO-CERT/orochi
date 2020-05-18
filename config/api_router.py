from django.conf import settings
from rest_framework.routers import DefaultRouter, SimpleRouter

from orochi.users.api.views import UserViewSet
from orochi.daskmanager.views import DaskTaskViewSet


if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

router.register("users", UserViewSet)
router.register("tasks", DaskTaskViewSet)


app_name = "api"
urlpatterns = router.urls
