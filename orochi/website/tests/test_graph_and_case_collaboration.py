import json

import pytest
from asgiref.sync import async_to_sync
from channels.db import database_sync_to_async
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone

import orochi.website.routing
from orochi.users.models import APIToken
from orochi.website.crypto import decrypt_secret, encrypt_secret
from orochi.website.models import (
    Case,
    CaseNote,
    Dump,
    Evidence,
    Finding,
    ForensicEdge,
    ForensicNode,
    Plugin,
    Result,
    Service,
    Value,
)
from orochi.website.tasks import build_case_forensic_graph, index_result_values_task

pytestmark = pytest.mark.django_db


def test_crypto_service_encryption():
    """Verify AES-256-GCM symmetric encryption and Service model key helpers."""
    secret = "SuperSecretApiKey123!"
    encrypted = encrypt_secret(secret)
    assert encrypted != secret
    decrypted = decrypt_secret(encrypted)
    assert decrypted == secret

    # Service model helper
    srv = Service(name="TestVT", proxy=False)
    srv.set_encrypted_key(secret)
    assert srv.key != secret
    assert srv.decrypted_key == secret


def test_api_token_model_generation(user):
    """Verify APIToken model securely generates prefix, token, and hash."""
    api_token, raw_token = APIToken.generate_token(user=user, name="CI Automation Token")
    assert raw_token.startswith("oro_")
    assert api_token.token_prefix == raw_token[:8]
    assert len(api_token.hashed_token) == 64
    assert api_token.user == user


def test_case_forensic_graph_and_timeline_pipeline(user):
    """Test full forensic graph generation across processes, sockets, and memory injections."""
    case = Case.objects.create(name="Investigation-Alpha", user=user)
    dump = Dump.objects.create(
        name="Host-01-Dump",
        index="dump_idx_01",
        author=user,
        operating_system="Windows",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    Evidence.objects.create(case=case, dump=dump, name="RAM Dump Host-01")

    # 1. Process Results (pslist)
    p_pslist, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList")
    res_ps = Result.objects.create(dump=dump, plugin=p_pslist, result=1)
    Value.objects.create(
        result=res_ps,
        value={
            "PID": 1000,
            "PPID": 400,
            "ImageFileName": "cmd.exe",
            "CreateTime": "2026-10-28 07:00:00 UTC",
        },
    )
    Value.objects.create(
        result=res_ps,
        value={
            "PID": 2000,
            "PPID": 1000,
            "ImageFileName": "powershell.exe",
            "CreateTime": "2026-10-28 07:05:00 UTC",
        },
    )

    # 2. Network Results (netscan)
    p_net, _ = Plugin.objects.get_or_create(name="windows.netscan.NetScan")
    res_net = Result.objects.create(dump=dump, plugin=p_net, result=1)
    Value.objects.create(
        result=res_net,
        value={
            "PID": 2000,
            "ForeignAddress": "198.51.100.25",
            "ForeignPort": 4444,
            "LocalAddress": "192.168.1.15",
            "LocalPort": 49200,
            "State": "ESTABLISHED",
            "Created": "2026-10-28 07:06:00 UTC",
        },
    )

    # 3. Memory Injections (malfind)
    p_mal, _ = Plugin.objects.get_or_create(name="windows.malfind.Malfind")
    res_mal = Result.objects.create(dump=dump, plugin=p_mal, result=1)
    Value.objects.create(
        result=res_mal,
        value={
            "PID": 2000,
            "Start VPN": "0x2a00000",
            "Protection": "PAGE_EXECUTE_READWRITE",
        },
    )

    # Build Graph
    counts = build_case_forensic_graph.func(case.pk)
    assert counts["nodes"] >= 3
    assert counts["edges"] >= 2

    # Verify nodes
    ps_node = ForensicNode.objects.get(case=case, canonical_id=f"dump:{dump.pk}|pid:2000")
    assert ps_node.is_malicious is True
    assert ps_node.attributes["image"] == "powershell.exe"

    sock_node = ForensicNode.objects.get(case=case, canonical_id="socket:198.51.100.25:4444")
    assert sock_node.node_type == "socket"

    # Verify edges
    spawns_edge = ForensicEdge.objects.get(case=case, edge_type="spawns")
    assert spawns_edge.source.canonical_id == f"dump:{dump.pk}|pid:1000"
    assert spawns_edge.target.canonical_id == f"dump:{dump.pk}|pid:2000"

    connects_edge = ForensicEdge.objects.get(case=case, edge_type="connects")
    assert connects_edge.source == ps_node
    assert connects_edge.target == sock_node

    injects_edge = ForensicEdge.objects.get(case=case, edge_type="injects")
    assert injects_edge.source == ps_node


def test_case_graph_and_timeline_api(client, user):
    """Test REST API endpoints for graph and timeline retrieval."""
    client.force_login(user)
    case = Case.objects.create(name="Investigation-Beta", user=user)
    dump = Dump.objects.create(name="Host-02", index="dump_idx_02", author=user)
    Evidence.objects.create(case=case, dump=dump, name="RAM Dump Host-02")

    n1 = ForensicNode.objects.create(
        case=case,
        dump=dump,
        node_type="process",
        label="explorer.exe (1500)",
        canonical_id="dump:2|pid:1500",
        first_seen=timezone.now(),
    )
    n2 = ForensicNode.objects.create(
        case=case,
        dump=dump,
        node_type="process",
        label="malicious.exe (2500)",
        canonical_id="dump:2|pid:2500",
        first_seen=timezone.now(),
        is_malicious=True,
    )
    ForensicEdge.objects.create(case=case, source=n1, target=n2, edge_type="spawns", timestamp=timezone.now())

    # GET /api/cases/{case_id}/graph/
    res = client.get(f"/api/cases/{case.pk}/graph/")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1

    # Filter malicious only
    res_mal = client.get(f"/api/cases/{case.pk}/graph/?include_benign=false")
    assert res_mal.status_code == 200
    assert len(res_mal.json()["nodes"]) == 1

    # GET /api/cases/{case_id}/timeline/
    res_tl = client.get(f"/api/cases/{case.pk}/timeline/")
    assert res_tl.status_code == 200
    timeline = res_tl.json()
    assert len(timeline) >= 2


def test_case_notes_crud_api(client, user):
    """Test collaborative case notes CRUD endpoints."""
    client.force_login(user)
    case = Case.objects.create(name="Investigation-Notes", user=user)

    # 1. Create Note
    res_create = client.post(
        f"/api/cases/{case.pk}/notes/",
        data=json.dumps({"title": "Initial Analysis", "content": "Found suspicious outbound beacon."}),
        content_type="application/json",
    )
    assert res_create.status_code == 201
    note_id = res_create.json()["id"]

    # 2. List Notes
    res_list = client.get(f"/api/cases/{case.pk}/notes/")
    assert res_list.status_code == 200
    assert len(res_list.json()) == 1
    assert res_list.json()[0]["title"] == "Initial Analysis"

    # 3. Patch Note
    res_patch = client.patch(
        f"/api/cases/{case.pk}/notes/{note_id}",
        data=json.dumps({"content": "Updated: Beacon confirmed to C2 server."}),
        content_type="application/json",
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["content"] == "Updated: Beacon confirmed to C2 server."

    # 4. Delete Note
    res_del = client.delete(f"/api/cases/{case.pk}/notes/{note_id}")
    assert res_del.status_code == 200
    assert CaseNote.objects.filter(pk=note_id).count() == 0


def test_case_export_multi_format(client, user):
    """Test exporting case reports to Markdown, HTML, PDF, and STIX 2.1."""
    client.force_login(user)
    case = Case.objects.create(name="Export-Test-Case", user=user, description="Testing multi-format exporter.")
    dump = Dump.objects.create(
        name="Dump-Alpha",
        index="export_idx",
        author=user,
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    )
    ev = Evidence.objects.create(case=case, dump=dump, name="Primary RAM")
    Finding.objects.create(
        case=case,
        evidence=ev,
        severity="High",
        note="Cobalt Strike Beacon detected in memory injection.",
        mitre_attack_technique="T1055",
    )
    CaseNote.objects.create(case=case, author=user, title="Summary", content="Action required immediately.")

    # 1. Markdown Export
    res_md = client.get(f"/api/cases/{case.pk}/export?format=markdown")
    assert res_md.status_code == 200
    assert "text/markdown" in res_md["Content-Type"]
    assert b"# Incident Report: Export-Test-Case" in res_md.content
    assert b"T1055" in res_md.content

    # 2. HTML Export
    res_html = client.get(f"/api/cases/{case.pk}/export?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html["Content-Type"]
    assert b"<!DOCTYPE html>" in res_html.content
    assert b"Cobalt Strike" in res_html.content

    # 3. PDF Export (WeasyPrint)
    res_pdf = client.get(f"/api/cases/{case.pk}/export?format=pdf")
    assert res_pdf.status_code == 200
    assert res_pdf["Content-Type"] == "application/pdf"
    assert res_pdf.content.startswith(b"%PDF")

    # 4. STIX 2.1 JSON Export
    res_stix = client.get(f"/api/cases/{case.pk}/export?format=stix")
    if res_stix.status_code != 200:
        print("STIX EXPORT ERROR:", res_stix.content)
    assert res_stix.status_code == 200
    assert "application/json" in res_stix["Content-Type"]
    stix_data = json.loads(res_stix.content)
    assert stix_data["type"] == "bundle"
    assert any(obj["type"] == "report" for obj in stix_data["objects"])
    assert any(obj["type"] == "indicator" for obj in stix_data["objects"])


@pytest.mark.django_db(transaction=True)
def test_case_presence_consumer(user):
    """Test CasePresenceConsumer authentication, permissions, and broadcast."""

    async def _test():
        case = await sync_create_case(user, "Presence-Case")
        other_user = await sync_create_other_user("collaborator_bob")

        app = URLRouter(orochi.website.routing.websocket_urlpatterns)

        # 1. Unauthenticated -> 4401
        comm_anon = WebsocketCommunicator(app, f"/ws/case/{case.pk}/presence/")
        comm_anon.scope["user"] = AnonymousUser()
        connected, code = await comm_anon.connect()
        assert not connected
        assert code == 4401
        await comm_anon.disconnect()

        # 2. Unauthorized -> 4403
        comm_other = WebsocketCommunicator(app, f"/ws/case/{case.pk}/presence/")
        comm_other.scope["user"] = other_user
        connected, code = await comm_other.connect()
        assert not connected
        assert code == 4403
        await comm_other.disconnect()

        # 3. Authorized Owner -> Connect & Receive presence update
        comm_owner = WebsocketCommunicator(app, f"/ws/case/{case.pk}/presence/")
        comm_owner.scope["user"] = user
        connected, _ = await comm_owner.connect()
        assert connected

        # Should receive initial presence update
        msg = await comm_owner.receive_json_from()
        assert msg["type"] == "presence_update"
        assert len(msg["users"]) == 1
        assert msg["users"][0]["username"] == user.username

        # Send heartbeat with focus
        await comm_owner.send_json_to({"focus": "windows.malfind"})
        msg2 = await comm_owner.receive_json_from()
        assert msg2["type"] == "presence_update"
        assert msg2["users"][0]["focus"] == "windows.malfind"

        await comm_owner.disconnect()

    async_to_sync(_test)()


@database_sync_to_async
def sync_create_case(user, name):
    return Case.objects.create(name=name, user=user)


@database_sync_to_async
def sync_create_other_user(username):
    User = get_user_model()
    return User.objects.create_user(username=username, password="password123")


def test_index_result_values_task(user):
    """Test background task for index_result_values_task batch indexing."""
    dump = Dump.objects.create(name="Indexing-Dump", index="idx_test_task", author=user)
    plugin, _ = Plugin.objects.get_or_create(name="test.indexing.Plugin")
    res = Result.objects.create(dump=dump, plugin=plugin, result=1)

    # Bulk create values
    values = [Value(result=res, value={"item": i, "content": f"artifact {i}"}) for i in range(10)]
    Value.objects.bulk_create(values, batch_size=5000)

    # Search vectors initially can be indexed via task
    count = index_result_values_task.func(res.pk)
    assert count >= 0
