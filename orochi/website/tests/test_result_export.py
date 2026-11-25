"""Regression tests for Issue #1559: server-side full-result export in CSV, JSON, XLSX, and XML."""

import csv
import io
import json
import zipfile
from xml.etree import ElementTree as ET

import pytest
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Plugin, Result, Value

pytestmark = pytest.mark.django_db


def _seed_large_result(dump, row_count: int = 55):
    plugin, _ = Plugin.objects.get_or_create(
        name="windows.handles.Handles",
        defaults={"operating_system": "Windows"},
    )
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    rows = []
    for i in range(row_count):
        name = f"Handle <{i}> & \"quoted\" 'single' \x07ctrl" if i == 0 else f"Handle_{i}"
        rows.append(Value(result=res, value={"PID": 1000 + i, "Name": name, "Type": "File"}))
    Value.objects.bulk_create(rows)
    return plugin, res


@pytest.mark.parametrize("fmt", ["csv", "json", "xlsx", "xml"])
def test_server_side_export_contains_all_rows_and_identifies_dump_and_plugin(client, admin, dump, fmt):
    """AC1 & AC3 (#1559): Export returns all rows (>1 page) and filename names dump and plugin."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    row_count = 55
    plugin, _ = _seed_large_result(dump, row_count=row_count)

    url = reverse("website:export_plugin_result")
    resp = client.get(url, {"indexes[]": [str(dump.index)], "plugin": plugin.name, "format": fmt})
    assert resp.status_code == 200

    cd = resp["Content-Disposition"]
    assert f".{fmt}" in cd
    assert dump.name.replace(" ", "_") in cd
    assert "Handles" in cd

    if fmt == "csv":
        reader = list(csv.reader(io.StringIO(resp.content.decode("utf-8"))))
        assert len(reader) == row_count + 1  # header + all rows
        assert "PID" in reader[0]
    elif fmt == "json":
        parsed = json.loads(resp.content.decode("utf-8"))
        assert isinstance(parsed, list)
        assert len(parsed) == row_count
        assert parsed[0]["PID"] == 1000
    elif fmt == "xml":
        root = ET.fromstring(resp.content)
        xml_rows = root.findall("row")
        assert len(xml_rows) == row_count
        # Special characters must survive intact and XML must be well-formed
        first_name = xml_rows[0].find("Name").text
        assert "<0> & \"quoted\" 'single'" in first_name
    elif fmt == "xlsx":
        with zipfile.ZipFile(io.BytesIO(resp.content), "r") as zf:
            sheet_xml = zf.read("xl/worksheets/sheet1.xml")
        root = ET.fromstring(sheet_xml)
        ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        xlsx_rows = root.findall(".//s:sheetData/s:row", ns)
        assert len(xlsx_rows) == row_count + 1  # header + all rows


def test_export_plugin_result_rejects_unauthorized_user(client, user, dump):
    """Unauthorized users receive HTTP 403."""
    client.force_login(user)
    plugin, _ = _seed_large_result(dump, row_count=5)
    url = reverse("website:export_plugin_result")
    resp = client.get(url, {"indexes[]": [str(dump.index)], "plugin": plugin.name, "format": "csv"})
    assert resp.status_code == 403
