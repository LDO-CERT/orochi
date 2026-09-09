import pytest
from django.urls import reverse

from orochi.utils.timeliner import (
    build_timeline_feed,
    categorize_event,
    clean_bodywork,
    extract_timeline_entries,
    format_relative_delta,
    format_timespan,
    parse_body_line,
)
from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import DumpSecret, Plugin, Result, TriageFinding, Value

pytestmark = pytest.mark.django_db


# =====================================================================
# 1. Unit Tests: Timeliner Engine Utilities
# =====================================================================
def test_categorize_event():
    """Verify correct categorization based on plugin name and event description."""
    assert (
        categorize_event("windows.pslist.PsList", "svchost.exe pid 1024") == "process"
    )
    assert (
        categorize_event("windows.pstree.PsTree", "cmd.exe spawned by explorer")
        == "process"
    )
    assert categorize_event("linux.psscan.PsScan", "kernel thread") == "process"

    assert (
        categorize_event("windows.netscan.NetScan", "TCP 192.168.1.50:445") == "network"
    )
    assert (
        categorize_event("linux.sockstat.Sockstat", "socket listening on 8080")
        == "network"
    )

    assert (
        categorize_event("windows.filescan.FileScan", r"C:\Windows\System32\cmd.exe")
        == "filesystem"
    )
    assert (
        categorize_event("windows.mftscan.MFTScan", "File creation event")
        == "filesystem"
    )

    assert (
        categorize_event("windows.cmdline.CmdLine", "powershell -enc AAAA") == "command"
    )
    assert categorize_event("linux.bash.Bash", "whoami && id") == "command"

    assert (
        categorize_event("windows.registry.printkey.PrintKey", "RunOnce key added")
        == "registry"
    )
    assert (
        categorize_event("windows.registry.userassist.UserAssist", "Count 15")
        == "registry"
    )

    # Fallback to system
    assert categorize_event("unknown_plugin", "random hardware or module") == "system"


def test_format_relative_delta_and_timespan():
    """Verify relative delta badges and timespan string formatting."""
    assert format_relative_delta(0) == "+0s"
    assert format_relative_delta(15) == "+15s"
    assert format_relative_delta(125) == "+2m 5s"
    assert format_relative_delta(3665) == "+1h 1m"
    assert format_relative_delta(90000) == "+1d 1h"

    assert format_timespan(45) == "45 seconds"
    assert format_timespan(185) == "3 minutes"
    assert format_timespan(7300) == "2 hours, 1 mins"
    assert format_timespan(90000) == "1 days, 1 hours"


def test_build_timeline_feed_empty():
    """Verify feed generation when given no entries."""
    feed = build_timeline_feed([])
    assert feed["events"] == []
    assert feed["histogram"] == []
    assert feed["categories"] == []
    assert feed["stats"]["total_events"] == 0
    assert feed["stats"]["timespan_display"] == "0s"


def test_build_timeline_feed_with_events():
    """Verify chronological ordering, relative deltas, histogram calculation and category counts."""
    raw_entries = [
        {
            "id": 1,
            "value_id": 101,
            "Plugin": "windows.pslist.PsList",
            "Description": "svchost.exe PID 400",
            "Date": "2026-03-01T10:00:00Z",
            "dump_name": "Dump A",
            "dump_index": "idx-a",
            "dump_color": "#ff0000",
        },
        {
            "id": 2,
            "value_id": 102,
            "Plugin": "windows.cmdline.CmdLine",
            "Description": "cmd.exe /c whoami",
            "Date": "2026-03-01T10:05:00Z",
            "dump_name": "Dump A",
            "dump_index": "idx-a",
            "dump_color": "#ff0000",
        },
        {
            "id": 3,
            "value_id": 103,
            "Plugin": "windows.netscan.NetScan",
            "Description": "TCP 10.0.0.5:4444 ESTABLISHED",
            "Date": "2026-03-01T10:10:00Z",
            "dump_name": "Dump A",
            "dump_index": "idx-a",
            "dump_color": "#ff0000",
        },
    ]

    feed = build_timeline_feed(raw_entries)
    assert feed["stats"]["total_events"] == 3
    assert feed["stats"]["timespan_display"] == "10 minutes"
    assert feed["stats"]["earliest_date"].startswith("2026-03-01 10:00:00")
    assert feed["stats"]["latest_date"].startswith("2026-03-01 10:10:00")

    events = feed["events"]
    assert len(events) == 3
    # Check chronological ordering and relative deltas
    assert events[0]["relative_delta"] == "+0s"
    assert events[0]["category"] == "process"
    assert events[1]["relative_delta"] == "+5m 0s"
    assert events[1]["category"] == "command"
    assert events[2]["relative_delta"] == "+10m 0s"
    assert events[2]["category"] == "network"

    # Histogram buckets
    assert len(feed["histogram"]) == 30
    total_histogram_events = sum(b["count"] for b in feed["histogram"])
    assert total_histogram_events == 3


def test_extract_timeline_entries_from_values():
    """Verify extracting timeline entries from DB Value objects or dicts."""
    values = [
        {
            "id": 55,
            "value": {
                "Plugin": "windows.pslist.PsList",
                "Description": "Process spawned",
                "Created Date": "2026-02-15T12:00:00",
            },
        },
        {
            "id": 56,
            "value": {
                "Plugin": "windows.netscan.NetScan",
                "Description": "Connection established",
                "Modified Date": "2026-02-15T12:01:00",
            },
        },
    ]
    entries = extract_timeline_entries(
        values=values,
        dump_name="Win10-Dump",
        dump_index="dump-123",
        dump_color="#10b981",
    )
    assert len(entries) == 2
    assert entries[0]["Plugin"] == "windows.pslist.PsList"
    assert entries[0]["dump_name"] == "Win10-Dump"
    assert entries[0]["dump_color"] == "#10b981"
    assert entries[1]["Date"] == "2026-02-15T12:01:00"


# =====================================================================
# 2. Integration Tests: UI Analysis View with Timeliner
# =====================================================================
def test_analysis_view_timeliner_feed(client, admin, dump):
    """Test analysis view when plugin is timeliner.Timeliner injects timeline_feed into partial_analysis."""
    client.force_login(admin)

    timeliner_plugin = Plugin.objects.create(
        name="timeliner.Timeliner", operating_system="Linux"
    )
    res = Result.objects.create(
        dump=dump,
        plugin=timeliner_plugin,
        result=RESULT_STATUS_SUCCESS,
        description="Completed",
    )
    Value.objects.create(
        result=res,
        value={
            "Plugin": "linux.pslist.PsList",
            "Description": "sshd spawned PID 1200",
            "Created Date": "2026-01-01T08:00:00Z",
        },
    )
    Value.objects.create(
        result=res,
        value={
            "Plugin": "linux.sockstat.Sockstat",
            "Description": "TCP socket listening on port 22",
            "Created Date": "2026-01-01T08:02:30Z",
        },
    )

    url = reverse("website:analysis")
    response = client.get(
        url,
        {"indexes[]": [dump.index], "plugin": "timeliner.Timeliner"},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )

    assert response.status_code == 200
    content = response.content.decode("utf-8")

    # Check that Timesketch timeline components are rendered
    assert "Forensic Timeline Stream" in content
    assert "Timesketch Engine" in content
    assert "Activity Density &amp; Velocity Histogram" in content
    assert "timeline-stream-container" in content
    assert "example-table-container" in content
    assert "btn-timeline-stream-view" in content
    assert "btn-timeline-grid-view" in content
    assert "sshd spawned PID 1200" in content
    assert "+2m 30s" in content


# =====================================================================
# 3. Integration Tests: REST API GET /api/dumps/{index}/timeline
# =====================================================================
def test_dump_timeline_api_authenticated(client, admin, dump):
    """Test GET /api/dumps/{index}/timeline returns structured timeline data."""
    client.force_login(admin)

    timeliner_plugin = Plugin.objects.create(
        name="timeliner.Timeliner", operating_system="Linux"
    )
    res = Result.objects.create(
        dump=dump,
        plugin=timeliner_plugin,
        result=RESULT_STATUS_SUCCESS,
        description="Completed",
    )
    Value.objects.create(
        result=res,
        value={
            "Plugin": "windows.pslist.PsList",
            "Description": "svchost.exe PID 400",
            "Created Date": "2026-04-01T12:00:00Z",
        },
    )

    url = f"/api/dumps/{dump.index}/timeline"
    response = client.get(url)
    assert response.status_code == 200
    data = response.json()

    assert data["dump_index"] == dump.index
    assert data["dump_name"] == dump.name
    assert "stats" in data
    assert data["stats"]["total_events"] == 1
    assert "categories" in data
    assert "histogram" in data
    assert len(data["histogram"]) == 1 or len(data["histogram"]) == 30
    assert "events" in data
    assert len(data["events"]) == 1
    assert data["events"][0]["plugin"] == "windows.pslist.PsList"
    assert data["events"][0]["category"] == "process"


def test_dump_timeline_api_unauthorized(client, dump):
    """Test unauthorized access without permission returns 401 or 403."""
    url = f"/api/dumps/{dump.index}/timeline"
    # Unauthenticated
    response = client.get(url)
    assert response.status_code == 401


# =====================================================================
# 4. High-Density & Performance Tests: 33k Events in 29 Seconds
# =====================================================================
def test_format_relative_delta_subsecond():
    """Verify sub-second precision for small fractional deltas."""
    assert format_relative_delta(0.25) == "+0.25s"
    assert format_relative_delta(1.50) == "+1.50s"
    assert format_relative_delta(9.99) == "+9.99s"
    # Over 10s or integer returns clean seconds
    assert format_relative_delta(15.4) == "+15s"
    assert format_relative_delta(0) == "+0s"


def test_high_density_short_duration_adaptive_binning():
    """Verify that 33,000 events in a 29-second duration produces 29 1-second discrete buckets."""
    base_ts = 1700000000
    events = []
    for i in range(33000):
        ts = base_ts + (i % 29)
        events.append(
            {
                "id": f"ev-{i}",
                "value_id": i,
                "Plugin": "windows.pslist.PsList",
                "Description": f"Process {i}",
                "Date": ts,
                "dump_name": "Dump Fast",
                "dump_index": "dump-fast",
                "dump_color": "#3b82f6",
            }
        )

    feed = build_timeline_feed(events, limit=50)

    # Stats validation
    assert feed["stats"]["total_events"] == 33000
    assert (
        "28 seconds" in feed["stats"]["timespan_display"]
        or "29 seconds" in feed["stats"]["timespan_display"]
    )

    # Adaptive binning: 29 buckets for 28-29s timespan
    histogram = feed["histogram"]
    assert len(histogram) == 29
    assert sum(b["count"] for b in histogram) == 33000

    # Bucket 0 and last bucket labels have distinct seconds and relative offsets
    assert "(+0s)" in histogram[0]["start"]
    assert "(+28s)" in histogram[-1]["start"]
    assert histogram[0]["start_ts"] == base_ts
    assert histogram[0]["end_ts"] == base_ts + 1.0

    # Compact JSON is generated and contains records
    assert "compact_events" in feed
    assert len(feed["compact_events"]) == 33000
    assert "compact_events_json" in feed
    assert len(feed["compact_events_json"]) > 1000


def test_analysis_view_timeliner_feed_compact_data(client, admin, dump):
    """Test analysis view renders embedded JSON script and scroll sentinel for fast client hydration."""
    client.force_login(admin)

    timeliner_plugin = Plugin.objects.create(
        name="timeliner.Timeliner", operating_system="Linux"
    )
    res = Result.objects.create(
        dump=dump,
        plugin=timeliner_plugin,
        result=RESULT_STATUS_SUCCESS,
        description="Completed",
    )
    Value.objects.create(
        result=res,
        value={
            "Plugin": "windows.pslist.PsList",
            "Description": "svchost.exe PID 100",
            "Created Date": "2026-05-01T10:00:00Z",
        },
    )

    url = reverse("website:analysis")
    response = client.get(
        url,
        {"indexes[]": [dump.index], "plugin": "timeliner.Timeliner"},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )

    assert response.status_code == 200
    content = response.content.decode("utf-8")

    assert "timeline-events-data" in content
    assert "timeline-scroll-sentinel" in content
    assert "content-visibility: auto" in content
    assert "svchost.exe PID 100" in content


# =====================================================================
# 5. Option 2: Forensic MACB Badges, Adaptive Plotly & Threat Overlays
# =====================================================================
def test_macb_parsing_sleuthkit_bodyfile():
    """Verify MACB timestamp parsing from SleuthKit BodyFile v3 lines."""
    # Full MACB
    line_all = "0|windows.filescan.FileScan - C:\\test.exe|0|0|0|0|0|1700000001|1700000002|1700000003|1700000004"
    res = parse_body_line(line_all)
    assert res["macb"] == "MACB"
    assert res["atime"] == 1700000001
    assert res["mtime"] == 1700000002
    assert res["ctime"] == 1700000003
    assert res["crtime"] == 1700000004
    assert res["Date"] is not None

    # Partial: M..B (Modified & Born only)
    line_mb = "0|[windows.filescan.FileScan] C:\\windows\\cmd.exe|0|0|0|0|0|0|1700000100|0|1700000200"
    res_mb = parse_body_line(line_mb)
    assert res_mb["macb"] == "M..B"
    assert res_mb["Plugin"] == "windows.filescan.FileScan"
    assert res_mb["Description"] == "C:\\windows\\cmd.exe"
    assert res_mb["Date"] is not None

    # Partial: .A.. (Accessed only)
    line_a = "0|windows.pslist.PsList - svchost.exe|0|0|0|0|0|1700000300|0|0|0"
    res_a = parse_body_line(line_a)
    assert res_a["macb"] == ".A.."

    # Single timestamp fallback
    line_single = "windows.netscan.NetScan - socket|1700000400"
    res_single = parse_body_line(line_single)
    assert res_single["Date"] is not None


def test_macb_extraction_from_values():
    """Verify MACB extraction from database values dictionary."""
    values = [
        {
            "id": 1,
            "value": {
                "Plugin": "windows.filescan.FileScan",
                "Description": "C:\\temp\\malware.exe",
                "Created Date": "2026-03-01T10:00:00Z",
                "Modified Date": "2026-03-01T10:05:00Z",
            },
        },
        {
            "id": 2,
            "value": {
                "Plugin": "windows.pslist.PsList",
                "Description": "svchost.exe PID 500",
                "Accessed Date": "2026-03-01T10:10:00Z",
                "Changed Date": "2026-03-01T10:15:00Z",
            },
        },
    ]
    entries = extract_timeline_entries(values=values)
    assert len(entries) == 2
    assert entries[0]["macb"] == "M..B"
    assert entries[1]["macb"] == ".AC."


def test_clean_bodywork_adaptive_buttons_and_decimation():
    """Verify clean_bodywork generates adaptive range buttons and preserves priority categories."""
    # 1. Short burst (<= 300s): should produce second/minute buttons (10s, 30s, 1m, 2m)
    short_values = [
        {
            "Plugin": "windows.pslist.PsList",
            "Description": "Process A",
            "Date": 1700000000,
        },
        {
            "Plugin": "windows.cmdline.CmdLine",
            "Description": "Command B",
            "Date": 1700000025,
        },
    ]
    html_short = clean_bodywork(values=short_values)
    assert "10s" in html_short
    assert "30s" in html_short
    assert "1m" in html_short
    assert "2m" in html_short

    # 2. Multi-day timeline (> 86400s): should produce day/hour buttons (1h, 6h, 1d, 7d)
    long_values = [
        {
            "Plugin": "windows.pslist.PsList",
            "Description": "Process A",
            "Date": 1700000000,
        },
        {
            "Plugin": "windows.cmdline.CmdLine",
            "Description": "Command B",
            "Date": 1700300000,
        },
    ]
    html_long = clean_bodywork(values=long_values)
    assert "1h" in html_long
    assert "6h" in html_long
    assert "1d" in html_long
    assert "7d" in html_long


def test_build_timeline_feed_threat_overlay(dump):
    """Verify threat findings and dump secrets are cross-referenced and annotated on timeline events."""
    tf = TriageFinding.objects.create(
        dump=dump,
        rule_id="RULE-INJECT",
        rule_name="Process Injection Detected",
        category="Injection",
        severity="Critical",
        score=95,
        mitre_technique="T1055",
        description="Injected thread found in svchost.exe PID 1024",
        entity="PID 1024",
    )
    secret = DumpSecret.objects.create(
        dump=dump,
        category="api_key",
        rule_name="AWS_Access_Key",
        matched_data="AKIAIOSFODNN7EXAMPLE",
        masked_data="AKIA****************",
        pid=2048,
        process_name="powershell.exe",
    )

    events = [
        {
            "id": "e1",
            "value_id": 1,
            "Plugin": "windows.pslist.PsList",
            "Description": "svchost.exe PID 1024 parent explorer.exe",
            "Date": 1700000000,
        },
        {
            "id": "e2",
            "value_id": 2,
            "Plugin": "windows.cmdline.CmdLine",
            "Description": "powershell.exe -enc AAAAAA PID 2048",
            "Date": 1700000010,
        },
        {
            "id": "e3",
            "value_id": 3,
            "Plugin": "windows.netscan.NetScan",
            "Description": "Normal TCP connection 192.168.1.1:80",
            "Date": 1700000020,
        },
    ]

    feed = build_timeline_feed(events, threat_findings=[tf], secrets=[secret])

    assert feed["stats"]["threat_count"] == 2
    # Check event 1 matched TriageFinding
    ev1 = feed["events"][0]
    assert ev1["threat"] is not None
    assert ev1["threat"]["severity"] == "Critical"
    assert ev1["threat"]["rule_name"] == "Process Injection Detected"
    assert ev1["threat"]["mitre"] == "T1055"

    # Check event 2 matched DumpSecret
    ev2 = feed["events"][1]
    assert ev2["threat"] is not None
    assert "Secret Leak" in ev2["threat"]["rule_name"]

    # Check event 3 clean
    ev3 = feed["events"][2]
    assert ev3["threat"] is None

    # Check histogram threat tracking
    assert any(b["has_threat"] for b in feed["histogram"])
    assert sum(b["threat_count"] for b in feed["histogram"]) == 2


def test_analysis_view_timeliner_3way_switcher_and_export(client, admin, dump):
    """Test analysis view renders 3-way view switcher, export dropdown, and MACB badges."""
    client.force_login(admin)

    timeliner_plugin = Plugin.objects.create(
        name="timeliner.Timeliner", operating_system="Linux"
    )
    res = Result.objects.create(
        dump=dump,
        plugin=timeliner_plugin,
        result=RESULT_STATUS_SUCCESS,
        description="Completed",
    )
    Value.objects.create(
        result=res,
        value={
            "Plugin": "windows.filescan.FileScan",
            "Description": "C:\\Windows\\System32\\cmd.exe",
            "Created Date": "2026-06-01T10:00:00Z",
            "Modified Date": "2026-06-01T10:02:00Z",
        },
    )

    url = reverse("website:analysis")
    response = client.get(
        url,
        {"indexes[]": [dump.index], "plugin": "timeliner.Timeliner"},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )

    assert response.status_code == 200
    content = response.content.decode("utf-8")

    # 3-way switcher buttons
    assert "btn-timeline-stream-view" in content
    assert "btn-timeline-scatter-view" in content
    assert "btn-timeline-grid-view" in content
    assert "Scatter &amp; Swimlanes" in content

    # Export dropdown
    assert "Export Filtered CSV" in content
    assert "Export BodyFile v3" in content
    assert "Export Timesketch JSONL" in content

    # MACB indicator
    assert "Forensic MACB" in content
    assert "M..B" in content or (
        "text-amber-500" in content and "text-emerald-500" in content
    )
