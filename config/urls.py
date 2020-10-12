from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path, re_path
from django.views import defaults as default_views
from django.views.generic import TemplateView

from rest_framework.authtoken.views import obtain_auth_token
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# DJANGO VIEWS
urlpatterns = [
    path(settings.ADMIN_URL, admin.site.urls),
    path("", include("orochi.website.urls", namespace="website")),
    path("users/", include("orochi.users.urls", namespace="users")),
    path("accounts/", include("allauth.urls")),
    path("upload/", include("django_file_form.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
if settings.DEBUG:
    urlpatterns += staticfiles_urlpatterns()

# API URLS
urlpatterns += [
    path("api/", include("config.api_router")),
    path("auth-token/", obtain_auth_token),
]

# SWAGGER
schema_view = get_schema_view(
    openapi.Info(title="Orochi API", default_version="v1"),
    public=True,
    permission_classes=(permissions.AllowAny,),
)
urlpatterns += [
    re_path(
        r"^swagger(?P<format>\.json)$",
        schema_view.without_ui(cache_timeout=0),
        name="schema-json",
    ),
    path(
        r"swagger/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    path(r"redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
]

if settings.DEBUG:
    urlpatterns += [
        path(
            "400/",
            default_views.bad_request,
            kwargs={"exception": Exception("Bad Request!")},
        ),
        path(
            "403/",
            default_views.permission_denied,
            kwargs={"exception": Exception("Permission Denied")},
        ),
        path(
            "404/",
            default_views.page_not_found,
            kwargs={"exception": Exception("Page not Found")},
        ),
        path("500/", default_views.server_error),
    ]
    if "debug_toolbar" in settings.INSTALLED_APPS:
        import debug_toolbar

        urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
