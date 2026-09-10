import datetime
from uuid import uuid4

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Dump, Host, Plugin, Result, Value
from orochi.website.temporal import (
    compute_temporal_diff,
    diff_common_plugins,
    diff_injected_regions,
    diff_network,
    diff_processes,
    format_duration,
    get_temporal_order,
)


@pytest.mark.django_db
def test_format_duration():
    assert format_duration(30) == "30s"
    assert format_duration(60) == "1m"
    assert format_duration(90) == "1m 30s"
    assert format_duration(3600) == "1h"
    assert format_duration(3665) == "1h 1m 5s"
    assert format_duration(90000) == "1d 1h"


@pytest.mark.django_db
def test_get_temporal_order_and_host(admin, folder):
    host1 = Host.objects.create(name="workstation-corp")

    dump1 = Dump.objects.create(
        name="dump_t1",
        operating_system="Windows",
        author=admin,
        folder=folder,
        host=host1,
        index=str(uuid4()),
        upload=SimpleUploadedFile("t1.raw", b"test content 1"),
    )
    # Set created_at explicitly
    Dump.objects.filter(pk=dump1.pk).update(created_at=timezone.now() - datetime.timedelta(hours=2))
    dump1.refresh_from_db()

    dump2 = Dump.objects.create(
        name="dump_t2",
        operating_system="Windows",
        author=admin,
        folder=folder,
        host=host1,
        index=str(uuid4()),
        upload=SimpleUploadedFile("t2.raw", b"test content 2"),
    )

    # Standard order (T1 is earlier)
    order = get_temporal_order(dump1, dump2)
    assert order["t1"].pk == dump1.pk
    assert order["t2"].pk == dump2.pk
    assert order["is_same_host"] is True
    assert order["host_name"] == "workstation-corp"
    assert order["delta_seconds"] > 7000

    # Reversed order
    order_rev = get_temporal_order(dump1, dump2, reverse=True)
    assert order_rev["t1"].pk == dump2.pk
    assert order_rev["t2"].pk == dump1.pk
    assert order_rev["is_reversed"] is True


@pytest.mark.django_db
def test_diff_processes(admin, folder):
    dump1 = Dump.objects.create(
        name="d1",
        operating_system="Windows",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("1.raw", b"1"),
    )
    dump2 = Dump.objects.create(
        name="d2",
        operating_system="Windows",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("2.raw", b"2"),
    )
    ps_plugin, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList", operating_system="Windows")

    res1 = Result.objects.create(dump=dump1, plugin=ps_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res1, value={"PID": 4, "ImageFileName": "System", "PPID": 0})
    Value.objects.create(result=res1, value={"PID": 100, "ImageFileName": "oldproc.exe", "PPID": 4})

    res2 = Result.objects.create(dump=dump2, plugin=ps_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res2, value={"PID": 4, "ImageFileName": "System", "PPID": 0})
    Value.objects.create(result=res2, value={"PID": 555, "ImageFileName": "beacon.exe", "PPID": 4})

    proc_diff = diff_processes(dump1, dump2)
    assert proc_diff["available"] is True
    assert proc_diff["new_count"] == 1
    assert proc_diff["terminated_count"] == 1
    assert proc_diff["persisted_count"] == 1
    assert proc_diff["new"][0]["name"] == "beacon.exe"
    assert proc_diff["new"][0]["pid"] == 555
    assert proc_diff["terminated"][0]["name"] == "oldproc.exe"
    assert proc_diff["persisted"][0]["name"] == "System"


@pytest.mark.django_db
def test_diff_injected_regions(admin, folder):
    dump1 = Dump.objects.create(
        name="d1",
        operating_system="Windows",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("1.raw", b"1"),
    )
    dump2 = Dump.objects.create(
        name="d2",
        operating_system="Windows",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("2.raw", b"2"),
    )
    malfind_plugin, _ = Plugin.objects.get_or_create(name="windows.malware.malfind.Malfind", operating_system="Windows")

    res1 = Result.objects.create(dump=dump1, plugin=malfind_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res1,
        value={
            "PID": 400,
            "Process": "explorer.exe",
            "Start": "0x10000",
            "End": "0x20000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "HexDump": "90 90 cc cc",
        },
    )

    res2 = Result.objects.create(dump=dump2, plugin=malfind_plugin, result=RESULT_STATUS_SUCCESS)
    # Explorer persists, but new injected region in svchost appears in T2
    Value.objects.create(
        result=res2,
        value={
            "PID": 400,
            "Process": "explorer.exe",
            "Start": "0x10000",
            "End": "0x20000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "HexDump": "90 90 cc cc",
        },
    )
    Value.objects.create(
        result=res2,
        value={
            "PID": 800,
            "Process": "svchost.exe",
            "Start": "0x50000",
            "End": "0x60000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "HexDump": "4d 5a 90 00 03 00 00 00",  # MZ header!
            "Disasm": "add [rax], al",
        },
    )

    inj_diff = diff_injected_regions(dump1, dump2)
    assert inj_diff["available"] is True
    assert inj_diff["new_count"] == 1
    assert inj_diff["persisted_count"] == 1
    assert inj_diff["new"][0]["process"] == "svchost.exe"
    assert inj_diff["new"][0]["has_pe"] is True


@pytest.mark.django_db
def test_diff_network(admin, folder):
    dump1 = Dump.objects.create(
        name="d1",
        operating_system="Windows",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("1.raw", b"1"),
    )
    dump2 = Dump.objects.create(
        name="d2",
        operating_system="Windows",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("2.raw", b"2"),
    )
    net_plugin, _ = Plugin.objects.get_or_create(name="windows.netscan.NetScan", operating_system="Windows")

    res1 = Result.objects.create(dump=dump1, plugin=net_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res1,
        value={
            "Proto": "TCP",
            "LocalAddr": "192.168.1.50",
            "LocalPort": 49152,
            "ForeignAddr": "1.1.1.1",
            "ForeignPort": 53,
            "State": "ESTABLISHED",
            "PID": 1000,
            "Owner": "dns.exe",
        },
    )

    res2 = Result.objects.create(dump=dump2, plugin=net_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res2,
        value={
            "Proto": "TCP",
            "LocalAddr": "192.168.1.50",
            "LocalPort": 49152,
            "ForeignAddr": "1.1.1.1",
            "ForeignPort": 53,
            "State": "ESTABLISHED",
            "PID": 1000,
            "Owner": "dns.exe",
        },
    )
    Value.objects.create(
        result=res2,
        value={
            "Proto": "TCP",
            "LocalAddr": "192.168.1.50",
            "LocalPort": 49200,
            "ForeignAddr": "203.0.113.88",
            "ForeignPort": 4444,
            "State": "ESTABLISHED",
            "PID": 555,
            "Owner": "beacon.exe",
        },
    )

    net_diff = diff_network(dump1, dump2)
    assert net_diff["available"] is True
    assert net_diff["new_count"] == 1
    assert net_diff["closed_count"] == 0
    assert net_diff["persisted_count"] == 1
    assert net_diff["new"][0]["foreign_port"] == "4444"
    assert net_diff["new"][0]["is_external"] is True


@pytest.mark.django_db
def test_diff_common_plugins(admin, folder):
    dump1 = Dump.objects.create(
        name="d1",
        operating_system="Windows",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("1.raw", b"1"),
    )
    dump2 = Dump.objects.create(
        name="d2",
        operating_system="Windows",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("2.raw", b"2"),
    )
    info_plugin, _ = Plugin.objects.get_or_create(name="windows.info.Info", operating_system="Windows")

    res1 = Result.objects.create(dump=dump1, plugin=info_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res1, value={"Variable": "MajorVersion", "Value": 10})

    res2 = Result.objects.create(dump=dump2, plugin=info_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res2, value={"Variable": "MajorVersion", "Value": 10})
    Value.objects.create(result=res2, value={"Variable": "MinorVersion", "Value": 0})

    common = diff_common_plugins(dump1, dump2)
    assert len(common) == 1
    assert common[0]["name"] == "windows.info.Info"
    assert common[0]["count_t1"] == 1
    assert common[0]["count_t2"] == 2
    assert common[0]["has_diff"] is True
    assert "diff_view" in common[0]["diff_url"]


@pytest.mark.django_db
def test_compute_temporal_diff(admin, folder):
    dump1 = Dump.objects.create(
        name="d1",
        operating_system="Linux",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("1.raw", b"1"),
    )
    dump2 = Dump.objects.create(
        name="d2",
        operating_system="Linux",
        author=admin,
        folder=folder,
        index=str(uuid4()),
        upload=SimpleUploadedFile("2.raw", b"2"),
    )

    diff = compute_temporal_diff(dump1, dump2)
    assert "meta" in diff
    assert "summary" in diff
    assert "processes" in diff
    assert "injected" in diff
    assert "network" in diff
    assert "common_plugins" in diff
    assert diff["summary"]["new_processes"] == 0
