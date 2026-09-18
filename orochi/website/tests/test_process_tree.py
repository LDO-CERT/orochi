import pytest
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import DumpSecret, Plugin, Result, TriageFinding, Value
from orochi.website.process_tree import _extract_pid, _format_offset, build_process_tree

pytestmark = pytest.mark.django_db


def create_plugin_values(dump, plugin_name, values):
    plugin, _ = Plugin.objects.get_or_create(
        name=plugin_name,
        defaults={"operating_system": dump.operating_system or "Windows"},
    )
    result = Result.objects.create(
        dump=dump,
        plugin=plugin,
        result=RESULT_STATUS_SUCCESS,
    )
    created = []
    created.extend(Value.objects.create(result=result, value=v) for v in values)
    return created


# ==============================================================================
# 1. Helper Function Tests
# ==============================================================================
def test_extract_pid_helper():
    assert _extract_pid(1234) == 1234
    assert _extract_pid("5678") == 5678
    assert _extract_pid("0x1a") == 26
    assert _extract_pid(None) is None
    assert _extract_pid("invalid") is None


def test_format_offset_helper():
    assert _format_offset(0xFA8000) == "0xfa8000"
    assert _format_offset("0xFA8000") == "0xFA8000"
    assert _format_offset(1000) == "0x3e8"
    assert _format_offset("") == ""
    assert _format_offset(None) == ""


# ==============================================================================
# 2. Process Tree Hierarchy Construction Tests
# ==============================================================================
def test_build_process_tree_from_pstree(admin, dump):
    """Test tree construction from windows.pstree.PsTree plugin output."""
    pstree_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "Offset(V)": "0xfa8000"},
        {"PID": 100, "PPID": 4, "ImageFileName": "smss.exe", "Offset(V)": "0xfa8100"},
        {"PID": 200, "PPID": 100, "ImageFileName": "csrss.exe", "Offset(V)": "0xfa8200"},
        {"PID": 300, "PPID": 100, "ImageFileName": "wininit.exe", "Offset(V)": "0xfa8300"},
        {"PID": 400, "PPID": 300, "ImageFileName": "services.exe", "Offset(V)": "0xfa8400"},
        {"PID": 500, "PPID": 400, "ImageFileName": "svchost.exe", "Offset(V)": "0xfa8500"},
    ]
    create_plugin_values(dump, "windows.pstree.PsTree", pstree_rows)

    tree = build_process_tree(dump)
    assert tree["dump"]["total_processes"] == 6
    assert tree["dump"]["source_plugin"] == "pstree"
    assert "4" in tree["roots"]

    # Verify edge connectivity
    edge_pairs = {(e["source"], e["target"]) for e in tree["edges"]}
    assert ("4", "100") in edge_pairs
    assert ("100", "200") in edge_pairs
    assert ("100", "300") in edge_pairs
    assert ("300", "400") in edge_pairs
    assert ("400", "500") in edge_pairs


def test_build_process_tree_fallback_pslist(admin, dump):
    """Test fallback to pslist when pstree is not run."""
    pslist_rows = [
        {"PID": 1, "PPID": 0, "COMM": "systemd", "Offset": "0x1000"},
        {"PID": 10, "PPID": 1, "COMM": "cron", "Offset": "0x2000"},
        {"PID": 20, "PPID": 1, "COMM": "sshd", "Offset": "0x3000"},
    ]
    create_plugin_values(dump, "linux.pslist.PsList", pslist_rows)

    tree = build_process_tree(dump)
    assert tree["dump"]["total_processes"] == 3
    assert tree["dump"]["source_plugin"] == "pslist"
    assert "1" in tree["roots"]

    edge_pairs = {(e["source"], e["target"]) for e in tree["edges"]}
    assert ("1", "10") in edge_pairs
    assert ("1", "20") in edge_pairs


def test_process_tree_cmdline_enrichment(admin, dump):
    """Test command line enrichment from cmdline plugin."""
    pstree_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 500, "PPID": 4, "ImageFileName": "powershell.exe"},
    ]
    create_plugin_values(dump, "windows.pstree.PsTree", pstree_rows)

    cmdline_rows = [
        {"PID": 500, "Process": "powershell.exe", "Args": "powershell.exe -enc SQBFAFgA"},
    ]
    create_plugin_values(dump, "windows.cmdline.CmdLine", cmdline_rows)

    tree = build_process_tree(dump)
    node_500 = next(n for n in tree["nodes"] if n["pid"] == 500)
    assert node_500["cmdline"] == "powershell.exe -enc SQBFAFgA"


def test_process_tree_threat_lineage_and_findings(admin, dump):
    """Test triage findings enrichment and infection chain flagging up to root."""
    pstree_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 100, "PPID": 4, "ImageFileName": "services.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": "svchost.exe"},
        {"PID": 666, "PPID": 200, "ImageFileName": "evil.exe"},
    ]
    create_plugin_values(dump, "windows.pstree.PsTree", pstree_rows)

    # Add a critical TriageFinding for PID 666
    TriageFinding.objects.create(
        dump=dump,
        rule_id="PROC_INJECTION",
        rule_name="Process Injection Detected",
        category="Injection",
        severity="Critical",
        score=90,
        mitre_technique="T1055",
        description="Injected code section in evil.exe",
        entity="PID: 666 (evil.exe)",
        raw_data={"PID": 666, "Process": "evil.exe"},
    )

    tree = build_process_tree(dump)
    node_666 = next(n for n in tree["nodes"] if n["pid"] == 666)
    assert node_666["is_flagged"] is True
    assert node_666["risk_level"] == "Critical"
    assert node_666["risk_score"] == 90
    assert len(node_666["findings"]) == 1
    assert node_666["findings"][0]["mitre_technique"] == "T1055"

    # Ancestor nodes 200, 100, 4 must have has_flagged_descendant == True
    node_200 = next(n for n in tree["nodes"] if n["pid"] == 200)
    node_100 = next(n for n in tree["nodes"] if n["pid"] == 100)
    node_4 = next(n for n in tree["nodes"] if n["pid"] == 4)

    assert node_200["has_flagged_descendant"] is True
    assert node_100["has_flagged_descendant"] is True
    assert node_4["has_flagged_descendant"] is True

    # Check edges flagged path
    flagged_edges = [e for e in tree["edges"] if e["is_compromised_path"]]
    assert len(flagged_edges) == 3


def test_process_tree_secrets_enrichment(admin, dump):
    """Test extracted secrets mapping to process node."""
    pstree_rows = [
        {"PID": 1234, "PPID": 0, "ImageFileName": "app.exe"},
    ]
    create_plugin_values(dump, "windows.pstree.PsTree", pstree_rows)

    DumpSecret.objects.create(
        dump=dump,
        rule_name="AWS_ACCESS_KEY",
        category="Cloud",
        matched_data="AKIAIOSFODNN7EXAMPLE",
        masked_data="AKIA****MPLE",
        pid=1234,
        process_name="app.exe",
    )

    tree = build_process_tree(dump)
    node = next(n for n in tree["nodes"] if n["pid"] == 1234)
    assert node["is_flagged"] is True
    assert node["secrets_count"] == 1
    assert node["secrets"][0]["rule_name"] == "AWS_ACCESS_KEY"


def test_process_tree_multi_root_and_orphans(admin, dump):
    """Test handling of multiple roots and orphaned processes."""
    pstree_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 888, "PPID": 99999, "ImageFileName": "orphaned.exe"},  # PPID 99999 not in dump
    ]
    create_plugin_values(dump, "windows.pstree.PsTree", pstree_rows)

    tree = build_process_tree(dump)
    assert "4" in tree["roots"]
    assert "888" in tree["roots"]
    assert len(tree["roots"]) == 2


# ==============================================================================
# 3. API & View Integration Tests
# ==============================================================================
def test_api_dump_process_tree(client, admin, dump):
    """Test REST API endpoint /api/dumps/{index}/process-tree."""
    assign_perm("website.can_see", admin, dump)
    client.force_login(admin)

    pstree_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 100, "PPID": 4, "ImageFileName": "smss.exe"},
    ]
    create_plugin_values(dump, "windows.pstree.PsTree", pstree_rows)

    url = f"/api/dumps/{dump.index}/process-tree"
    resp = client.get(url)
    assert resp.status_code == 200

    data = resp.json()
    assert data["dump"]["total_processes"] == 2
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1


def test_api_dump_process_tree_unauthorized(client, user, dump):
    """Test API rejects unauthorized users with 403."""
    client.force_login(user)
    url = f"/api/dumps/{dump.index}/process-tree"
    resp = client.get(url)
    assert resp.status_code == 403


def test_view_dump_process_tree_html(client, admin, dump):
    """Test full HTML page rendering."""
    assign_perm("website.can_see", admin, dump)
    client.force_login(admin)

    pstree_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
    ]
    create_plugin_values(dump, "windows.pstree.PsTree", pstree_rows)

    url = reverse("website:dump_process_tree", kwargs={"index": dump.index})
    resp = client.get(url)
    assert resp.status_code == 200
    content = resp.content.decode("utf-8")
    assert "Process Execution Tree" in content
    assert "ptree-raw-data" in content
    assert dump.name in content


def test_view_dump_process_tree_htmx(client, admin, dump):
    """Test partial HTMX rendering with focus PID."""
    assign_perm("website.can_see", admin, dump)
    client.force_login(admin)

    pstree_rows = [
        {"PID": 1234, "PPID": 0, "ImageFileName": "malware.exe"},
    ]
    create_plugin_values(dump, "windows.pstree.PsTree", pstree_rows)

    url = reverse("website:dump_process_tree", kwargs={"index": dump.index}) + "?focus=1234"
    resp = client.get(url, HTTP_HX_REQUEST="true")
    assert resp.status_code == 200
    content = resp.content.decode("utf-8")
    assert "process-tree-root" in content
    assert "1234" in content
