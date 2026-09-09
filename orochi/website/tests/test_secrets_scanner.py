import json

import pytest
from django.core.files import File
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Case, DumpSecret, Finding, Plugin, Result, Value
from orochi.website.secrets_scanner import (
    get_compiled_secrets_scanner,
    mask_secret,
    scan_dump_for_secrets,
)

pytestmark = pytest.mark.django_db


# =====================================================================
# 1. Unit Tests for Masking & Rule Compilation
# =====================================================================
def test_mask_secret():
    """Test partial masking for shoulder-surfing protection."""
    # AWS key
    masked_aws = mask_secret("AKIAIOSFODNN7EXAMPLE", "aws")
    assert masked_aws.startswith("AKIA")
    assert masked_aws.endswith("LE")
    assert "*" in masked_aws
    assert "IOSFODNN" not in masked_aws

    # Private key
    masked_pem = mask_secret("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "private_key")
    assert "BEGIN RSA PRIVATE KEY" in masked_pem
    assert "[KEY BODY REDACTED]" in masked_pem

    # JWT
    masked_jwt = mask_secret(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature", "jwt"
    )
    assert (
        masked_jwt
        == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[PAYLOAD REDACTED].[SIGNATURE REDACTED]"
    )

    # Generic
    masked_gen = mask_secret("abcdefgh")
    assert masked_gen.startswith("abc")
    assert "*" in masked_gen

    # Empty
    assert mask_secret("") == ""
    assert mask_secret(None) == ""


def test_compile_secrets_rules():
    """Verify YARA-X ruleset compiles without errors."""
    scanner = get_compiled_secrets_scanner()
    assert scanner is not None


# =====================================================================
# 2. Secrets Scanner on Structured Values & Files
# =====================================================================
def test_scan_dump_for_secrets_structured(admin, dump):
    """Test detecting secrets inside parsed plugin Value records."""
    assign_perm("website.can_see", admin, dump)

    # 1. Create cmdline plugin and result
    plugin_cmdline, _ = Plugin.objects.get_or_create(
        name="windows.cmdline.CmdLine",
        defaults={"operating_system": "Windows"},
    )
    result_cmdline = Result.objects.create(
        dump=dump,
        plugin=plugin_cmdline,
        result=RESULT_STATUS_SUCCESS,
    )
    Value.objects.create(
        result=result_cmdline,
        value={
            "PID": 4096,
            "Process": "cmd.exe",
            "CommandLine": "aws s3 sync s3://secret-bucket . --access-key AKIAIOSFODNN7EXAMPLE",
        },
    )

    # 2. Create bash plugin and result
    plugin_bash, _ = Plugin.objects.get_or_create(
        name="linux.bash.Bash",
        defaults={"operating_system": "Linux"},
    )
    result_bash = Result.objects.create(
        dump=dump,
        plugin=plugin_bash,
        result=RESULT_STATUS_SUCCESS,
    )
    Value.objects.create(
        result=result_bash,
        value={
            "PID": 1337,
            "Process": "bash",
            "Command": "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        },
    )

    # Run secrets scan
    found = scan_dump_for_secrets(dump)
    assert len(found) >= 2

    secrets = list(dump.secrets.all())
    categories = [s.category for s in secrets]
    assert "aws" in categories
    assert "api_key" in categories

    aws_secret = dump.secrets.get(category="aws")
    assert aws_secret.rule_name == "Secret_AWS_Access_Key"
    assert "AKIAIOSFODNN7EXAMPLE" in aws_secret.matched_data
    assert aws_secret.pid == 4096
    assert aws_secret.process_name == "cmd.exe"
    assert "*" in aws_secret.masked_data

    gh_secret = dump.secrets.get(category="api_key")
    assert gh_secret.rule_name == "Secret_GitHub_Token"
    assert "ghp_" in gh_secret.matched_data
    assert gh_secret.pid == 1337


def test_scan_dump_for_secrets_raw_memory(admin, dump, tmp_path):
    """Test detecting secrets from a raw dump file."""
    assign_perm("website.can_see", admin, dump)

    # Create dummy dump file with a private key
    fake_mem = tmp_path / "memory.dmp"
    raw_content = (
        b"Garbage prefix data 0123456789\n"
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEowIBAAKCAQEA0Y123456789abcdef\n"
        b"-----END RSA PRIVATE KEY-----\n"
        b"Garbage suffix data\n"
    )
    fake_mem.write_bytes(raw_content)

    with open(fake_mem, "rb") as f:
        dump.upload.save("memory.dmp", File(f))
    dump.save()

    found = scan_dump_for_secrets(dump)
    assert len(found) >= 1

    pem_secret = dump.secrets.filter(category="private_key").first()
    assert pem_secret is not None
    assert pem_secret.rule_name == "Secret_Private_Key_PEM"
    assert "BEGIN RSA PRIVATE KEY" in pem_secret.matched_data
    assert pem_secret.offset is not None


# =====================================================================
# 3. UI Views (dump_secrets & promote_to_finding)
# =====================================================================
def test_dump_secrets_view_get_and_post(client, admin, dump):
    """Test GET modal and POST re-scan in dump_secrets view."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    # Create an initial secret
    DumpSecret.objects.create(
        dump=dump,
        category="jwt",
        rule_name="Secret_JWT_Token",
        matched_data="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak",
        masked_data="eyJhb...leak",
        pid=500,
        process_name="node",
    )

    url = reverse("website:dump_secrets", kwargs={"index": dump.index})

    # 1. GET
    res_get = client.get(url)
    assert res_get.status_code == 200
    assert "Secrets & Credentials Hub" in res_get.content.decode()
    assert "Secret_JWT_Token" in res_get.content.decode()
    assert "eyJhb...leak" in res_get.content.decode()

    # 2. POST (Re-Scan)
    res_post = client.post(url)
    assert res_post.status_code == 200
    assert "Secrets & Credentials Hub" in res_post.content.decode()


def test_promote_secret_to_case_finding(client, admin, dump):
    """Test promoting a secret to a Case Finding via UI."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    case = Case.objects.create(name="Incident-Alpha", user=admin)
    secret = DumpSecret.objects.create(
        dump=dump,
        category="aws",
        rule_name="Secret_AWS_Access_Key",
        matched_data="AKIAIOSFODNN7EXAMPLE",
        masked_data="AKIA...MPLE",
        pid=123,
        process_name="powershell.exe",
    )

    promote_url = reverse("website:promote_to_finding")

    # 1. GET promotion modal
    res_get = client.get(f"{promote_url}?type=secret&id={secret.id}")
    assert res_get.status_code == 200
    content = res_get.content.decode()
    assert "Promote to Case Finding" in content
    assert "Incident-Alpha" in content

    # 2. POST promotion
    post_data = {
        "item_type": "secret",
        "item_id": secret.id,
        "case_id": case.id,
        "severity": "High",
        "mitre_technique": "T1552",
        "tags": "credential, aws",
        "note": "Exposed root AWS key in powershell process memory",
    }
    res_post = client.post(promote_url, post_data)
    assert res_post.status_code == 200
    assert "Promoted to Case Finding" in res_post.content.decode()

    # Check database records
    finding = Finding.objects.filter(case=case).first()
    assert finding is not None
    assert finding.severity == "High"
    assert finding.mitre_attack_technique == "T1552"
    assert "credential" in finding.tags
    assert finding.evidence is not None
    assert finding.evidence.plugin == "secrets_scanner"


# =====================================================================
# 4. REST API Endpoints
# =====================================================================
def test_api_dump_secrets(client, admin, dump):
    """Test REST API GET and POST secrets endpoints."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    DumpSecret.objects.create(
        dump=dump,
        category="aws",
        rule_name="Secret_AWS_Access_Key",
        matched_data="AKIAIOSFODNN7EXAMPLE",
        masked_data="AKIA...MPLE",
        pid=888,
        process_name="test.exe",
    )

    # 1. GET /api/dumps/{index}/secrets
    url_get = f"/api/dumps/{dump.index}/secrets"
    res_get = client.get(url_get)
    assert res_get.status_code == 200
    data = res_get.json()
    assert len(data) == 1
    assert data[0]["category"] == "aws"
    assert data[0]["rule_name"] == "Secret_AWS_Access_Key"
    assert data[0]["masked_data"] == "AKIA...MPLE"

    # 2. POST /api/dumps/promote_finding
    case = Case.objects.create(name="API Case", user=admin)
    promote_payload = {
        "case_id": case.id,
        "item_type": "secret",
        "item_id": data[0]["id"],
        "severity": "Critical",
        "mitre_technique": "T1552",
        "tags": ["api-promoted"],
    }
    res_promote = client.post(
        "/api/dumps/promote_finding",
        data=json.dumps(promote_payload),
        content_type="application/json",
    )
    assert res_promote.status_code == 201
    assert Finding.objects.filter(case=case, severity="Critical").exists()


# =====================================================================
# 5. Hex View Deep-Linking & Search Hardening Tests
# =====================================================================
def test_hex_view_deep_linking(client, admin, dump):
    """Test Hex View with initial_offset, initial_search, and back_to parameters."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    url = reverse("website:hex_view", kwargs={"index": dump.index})
    res = client.get(f"{url}?offset=0x1ed8ed22&search=sk-utility&back=secrets")
    assert res.status_code == 200
    html = res.content.decode()

    # Target Memory Focused banner
    assert "Target Memory Focused" in html
    assert "0x1ed8ed22" in html
    assert "sk-utility" in html

    # Back to Secrets button
    assert "Back to Secrets" in html
    assert reverse("website:dump_secrets", kwargs={"index": dump.index}) in html


def test_hex_view_back_to_triage(client, admin, dump):
    """Test Hex View with back_to=triage parameter."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    url = reverse("website:hex_view", kwargs={"index": dump.index})
    res = client.get(f"{url}?search=diamorphine&back=triage")
    assert res.status_code == 200
    html = res.content.decode()

    assert "Back to Triage" in html
    assert reverse("website:dump_triage", kwargs={"index": dump.index}) in html


def test_search_hex_regex_safe(client, admin, dump, tmp_path):
    """Test search_hex handles special regex characters without crashing."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    fake_mem = tmp_path / "memory_search.dmp"
    raw_content = b"prefix password(verifier)[*]+? suffix"
    fake_mem.write_bytes(raw_content)

    with open(fake_mem, "rb") as f:
        dump.upload.save("memory_search.dmp", File(f))
    dump.save()

    url = reverse("website:search_hex", kwargs={"index": dump.index})

    # Search with regex symbols: () [] * + ?
    res = client.get(url, {"findstr": "password(verifier)[*]+?", "last": 0})
    assert res.status_code == 200
    data = res.json()
    assert data["found"] == 1
    assert data["pos"] == 7


def test_secrets_hub_hex_view_buttons(client, admin, dump):
    """Test Secrets Hub renders Hex View button and clickable offset badge."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    DumpSecret.objects.create(
        dump=dump,
        category="password",
        rule_name="Secret_Generic_Credentials",
        matched_data="super_secret_passwd",
        masked_data="sup*****d",
        offset="0x1b1765c1",
        pid=1001,
        process_name="app.exe",
    )

    url = reverse("website:dump_secrets", kwargs={"index": dump.index})
    res = client.get(url)
    assert res.status_code == 200
    html = res.content.decode()

    # Clickable offset
    assert "@ 0x1b1765c1" in html
    assert "hex_view" in html
    assert "offset=0x1b1765c1" in html
    assert "back=secrets" in html

    # Dedicated Hex View button
    assert "Hex View" in html
