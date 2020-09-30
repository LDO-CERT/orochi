from django.urls import path, include
from django.conf import settings
from rest_framework_nested import routers

from orochi.users.api.views import UserViewSet
from orochi.website.api.views import DumpViewSet, ResultViewSet, PluginViewSet

if settings.DEBUG:
    router = routers.DefaultRouter()
else:
    router = routers.SimpleRouter()

router.register(r"users", UserViewSet)
router.register(r"dumps", DumpViewSet)
router.register(r"plugin", PluginViewSet)
dumps_router = routers.NestedSimpleRouter(router, r"dumps", lookup="dump")
dumps_router.register(r"results", ResultViewSet)

app_name = "api"
urlpatterns = [
    path(r"", include(router.urls)),
    path(r"", include(dumps_router.urls)),
]
