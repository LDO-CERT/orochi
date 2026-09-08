from uuid import uuid4

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Dump, Host, Plugin, Result, Value

pytestmark = pytest.mark.django_db


def test_api_temporal_diff_unauthenticated(client, dump):
    response = client.get(f"/api/dumps/temporal_diff/{dump.index}/{dump.index}")
    assert response.status_code in (401, 403)


def test_api_temporal_diff_authenticated(client, admin, dump, folder, user):
    client.force_login(admin)

    host = Host.objects.create(name="finance-pc")
    dump.host = host
    dump.save()

    dump2 = Dump.objects.create(
        name="dump_t2_api",
        operating_system="Windows",
        author=admin,
        folder=folder,
        host=host,
        index=str(uuid4()),
        upload=SimpleUploadedFile("t2.raw", b"test content 2"),
    )
    assign_perm("can_see", admin, dump2)

    ps_plugin, _ = Plugin.objects.get_or_create(
        name="windows.pslist.PsList", operating_system="Windows"
    )
    res1 = Result.objects.create(dump=dump, plugin=ps_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res1, value={"PID": 4, "ImageFileName": "System"})

    res2 = Result.objects.create(dump=dump2, plugin=ps_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res2, value={"PID": 4, "ImageFileName": "System"})
    Value.objects.create(result=res2, value={"PID": 777, "ImageFileName": "trojan.exe"})

    url = f"/api/dumps/temporal_diff/{dump.index}/{dump2.index}"
    response = client.get(url)
    assert response.status_code == 200
    data = response.json()

    assert data["meta"]["is_same_host"] is True
    assert data["meta"]["host_name"] == "finance-pc"
    assert data["summary"]["new_processes"] == 1
    assert data["processes"]["new_count"] == 1
    assert data["processes"]["new"][0]["name"] == "trojan.exe"

    # Test reverse parameter
    resp_rev = client.get(f"{url}?reverse=true")
    assert resp_rev.status_code == 200
    data_rev = resp_rev.json()
    assert data_rev["meta"]["is_reversed"] is True

    # Unauthorized access returns 403
    client.force_login(user)
    resp_unauth = client.get(url)
    assert resp_unauth.status_code == 403

    # Non-existent dump returns 404
    client.force_login(admin)
    resp_404 = client.get(f"/api/dumps/temporal_diff/{dump.index}/{uuid4()}")
    assert resp_404.status_code == 404
