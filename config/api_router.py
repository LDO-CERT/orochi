from django.urls import path, include
from django.conf import settings
from rest_framework_nested import routers

from orochi.users.api.views import UserViewSet
from orochi.website.api.views import DumpViewSet, ResultViewSet, PluginViewSet

if settings.DEBUG:
    router = routers.DefaultRouter()
else:
    router = routers.SimpleRouter()


# GET /users
# GET /users/<pk>
# POST /users/<pk>
# GET /users/me
router.register(r"users", UserViewSet)

# GET /dumps
# GET /dumps/<pk>
# POST /dumps/<pk>
router.register(r"dumps", DumpViewSet)

# GET /plugins
# GET /plugins/<pk>
router.register(r"plugin", PluginViewSet)

# GET /dumps/<pk>/results
# GET /dumps/<pk>/results/<pk>
# GET /dumps/<pk>/results/<pk>/resubmit
# GET /dumps/<pk>/results/<pk>/results
dumps_router = routers.NestedSimpleRouter(router, r"dumps", lookup="dump")
dumps_router.register(r"results", ResultViewSet)

# /dumps/<pk>/results/<pk>/extracted
# /dumps/<pk>/results/<pk>/extracted/<pk>
# /dumps/<pk>/results/<pk>/extracted/<pk>/vt
# /dumps/<pk>/results/<pk>/extracted/<pk>/clamav
# /dumps/<pk>/results/<pk>/extracted/<pk>/regipy


app_name = "api"
urlpatterns = [
    path(r"", include(router.urls)),
    path(r"", include(dumps_router.urls)),
]
