from django.conf import settings
from django.urls import include, path
from rest_framework_nested import routers

from orochi.users.api.views import UserViewSet
from orochi.website.api.views import DumpViewSet, PluginViewSet, ResultViewSet

if settings.DEBUG:
    router = routers.DefaultRouter()
else:
    router = routers.SimpleRouter()

router.register(r"users", UserViewSet)
router.register(r"dumps", DumpViewSet)
router.register(r"plugin", PluginViewSet)
dumps_router = routers.NestedSimpleRouter(router, r"dumps", lookup="dump")
dumps_router.register(r"results", ResultViewSet, basename="dump-plugins")
extdumps_router = routers.NestedSimpleRouter(dumps_router, r"results", lookup="result")

app_name = "api"
urlpatterns = [
    path(r"", include(router.urls)),
    path(r"", include(dumps_router.urls)),
    path(r"", include(extdumps_router.urls)),
]
