"""Regression tests for Issue #1549: strict STIX 2.1 IOC bundle export."""

import json

import pytest
import stix2

from orochi.website.ioc import export_iocs_to_stix
from orochi.website.models import DumpIOC

pytestmark = pytest.mark.django_db


def test_stix_ioc_bundle_strict_parse_ipv6_escaping_and_yara(dump):
    """AC1-AC4 (#1549): Bundle parses with allow_custom=False, uses ipv6-addr, escapes quotes, no match-all YARA."""
    iocs = [
        DumpIOC.objects.create(
            dump=dump,
            ioc_type="ip",
            value="203.0.113.42",
            source_plugin="windows.netscan.NetScan",
            is_malicious=True,
            threat_score=85,
        ),
        DumpIOC.objects.create(
            dump=dump,
            ioc_type="ip",
            value="2001:db8::dead:beef",
            source_plugin="windows.netscan.NetScan",
            is_malicious=True,
            threat_score=75,
        ),
        DumpIOC.objects.create(
            dump=dump,
            ioc_type="url",
            value="http://evil.example/path?a='quoted'&b=c\\d",
            source_plugin="windows.cmdline.CmdLine",
            is_malicious=True,
            threat_score=90,
        ),
        DumpIOC.objects.create(
            dump=dump,
            ioc_type="yara",
            value="APT_Beacon_Rule",
            source_plugin="yarascan.YaraScan",
            context={"pid": 1337, "process": "evil.exe", "offset": "0x400000"},
            is_malicious=True,
            threat_score=80,
        ),
        DumpIOC.objects.create(
            dump=dump,
            ioc_type="hash_sha256",
            value="a" * 64,
            source_plugin="windows.dumpfiles.DumpFiles",
            is_malicious=True,
            threat_score=95,
        ),
    ]

    bundle_dict = export_iocs_to_stix(dump, iocs)
    serialized = json.dumps(bundle_dict)

    # Strict STIX 2.1 parse with allow_custom=False MUST succeed
    parsed_bundle = stix2.parse(serialized, allow_custom=False)
    assert parsed_bundle.type == "bundle"

    indicators = [obj for obj in parsed_bundle.objects if obj.type == "indicator"]
    notes = [obj for obj in parsed_bundle.objects if obj.type == "note"]

    patterns = [ind.pattern for ind in indicators]
    assert "[ipv4-addr:value = '203.0.113.42']" in patterns
    assert "[ipv6-addr:value = '2001:db8::dead:beef']" in patterns
    assert "[url:value = 'http://evil.example/path?a=\\'quoted\\'&b=c\\\\d']" in patterns
    assert f"[file:hashes.'SHA-256' = '{'a' * 64}']" in patterns

    # No match-everything or wildcard file:name pattern allowed
    for pat in patterns:
        assert "MATCHES '.*'" not in pat
        assert "file:name" not in pat

    # YARA match is represented cleanly as a STIX Note
    assert any("APT_Beacon_Rule" in (n.abstract or "") for n in notes)
