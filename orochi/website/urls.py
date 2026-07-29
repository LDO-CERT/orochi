from uuid import UUID

from django.urls import path, register_converter

from orochi.website import views


class MultiindexConverter:
    regex = "[0-9a-f,-]{36,}"

    def valid_uuid(self, uuid):
        try:
            return UUID(uuid).version
        except ValueError:
            return None

    def to_python(self, value):
        return [x.strip() for x in value.split(",") if self.valid_uuid(x) is not None]

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
    path("indices", views.indices, name="indices"),
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
    path("info", views.info, name="index_info"),
    path("create", views.create, name="index_create"),
    path("edit", views.edit, name="index_edit"),
    path("restart", views.restart, name="index_restart"),
    path("analysis", views.analysis, name="analysis"),
    path("generate", views.generate, name="generate"),
    path("tree", views.tree, name="tree"),
    path("parameters", views.parameters, name="parameters"),
    path("export", views.export, name="export"),
    # FOLDERS
    path("folder_create", views.folder_create, name="folder_create"),
    # CASES / EVIDENCE
    path("case_create", views.case_create, name="case_create"),
    path("case_edit", views.case_edit, name="case_edit"),
    path("case_delete/<int:pk>", views.case_delete, name="case_delete"),
    path("case/<int:pk>", views.case_detail, name="case_detail"),
    path("case_export/<int:pk>", views.case_export, name="case_export"),
    path("case_report/<int:pk>", views.case_report, name="case_report"),
    path("evidence_create", views.evidence_create, name="evidence_create"),
    path(
        "finding_create/<int:evidence_pk>", views.finding_create, name="finding_create"
    ),
    path("finding_edit/<int:pk>", views.finding_edit, name="finding_edit"),
    path("finding_delete/<int:pk>", views.finding_delete, name="finding_delete"),
    # DOWNLOAD FILES
    path("download", views.download, name="download"),
    # EXTERNAL VIEW
    path("json_view/<path:filepath>", views.json_view, name="json_view"),
    path("hex_view/<str:index>", views.hex_view, name="hex_view"),
    path("get_hex/<str:index>", views.get_hex, name="get_hex"),
    path("search_hex/<str:index>", views.search_hex, name="search_hex"),
    path("vt", views.vt, name="vt"),
    path(
        "diff_view/<str:index_a>/<str:index_b>/<str:plugin>",
        views.diff_view,
        name="diff_view",
    ),
    # USER PAGE
    path("edit_bookmark", views.edit_bookmark, name="edit_bookmark"),
    path("add_bookmark", views.add_bookmark, name="add_bookmark"),
    # SYMBOLS
    path("banner_symbols", views.banner_symbols, name="banner_symbols"),
    path("upload_symbols", views.upload_symbols, name="upload_symbols"),
    path("upload_packages", views.upload_packages, name="upload_packages"),
    path("download_isf", views.download_isf, name="download_isf"),
    path("list_symbols", views.list_symbols, name="list_symbols"),
    # INTERNAL
    path("auth-check", views.auth_check, name="auth_check"),
]
