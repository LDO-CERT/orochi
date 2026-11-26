"""Exports are valid against their specification (#1674 FR-9)."""

import json
import re
from unittest.mock import MagicMock, patch

import pytest
from pymisp import MISPEvent

from orochi.website.attack import generate_navigator_layer
from orochi.website.defaults import SERVICE_MISP
from orochi.website.ioc import export_iocs_to_misp
from orochi.website.models import Case, DumpIOC, Finding, Service

pytestmark = pytest.mark.django_db

# ATT&CK Navigator layer format 4.5: required keys and value domains
NAVIGATOR_DOMAINS = {"enterprise-attack", "mobile-attack", "ics-attack"}
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def _validate_layer(layer: dict) -> None:
    assert isinstance(layer["name"], str) and layer["name"]
    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] in NAVIGATOR_DOMAINS
    for t in layer["techniques"]:
        assert TECHNIQUE_ID.match(t["techniqueID"]), t
        assert isinstance(t.get("score", 0), (int, float))
        assert t.get("color", "#000000").startswith("#")
    json.dumps(layer)  # serialisable as-is


@pytest.mark.parametrize(("technique", "domain"), [("T1055", "enterprise-attack"), ("T0843", "ics-attack")])
def test_navigator_layer_is_a_valid_4_5_layer(admin, technique, domain):
    case = Case.objects.create(name=f"Layer {technique}", user=admin)
    Finding.objects.create(case=case, severity="High", mitre_attack_technique=technique)
    layer = generate_navigator_layer(case, case.findings.all())
    _validate_layer(layer)
    assert layer["domain"] == domain and [t["techniqueID"] for t in layer["techniques"]] == [technique]


def test_misp_event_uses_valid_attribute_types(dump):
    Service.objects.create(name=SERVICE_MISP, url="https://misp.local", key="k")
    iocs = [
        DumpIOC.objects.create(dump=dump, ioc_type="ip", value="2001:db8::1", source_plugin="netscan", context={}),
        DumpIOC.objects.create(
            dump=dump, ioc_type="hash_sha256", value="a" * 64, source_plugin="dumpfiles", context={}
        ),
        DumpIOC.objects.create(dump=dump, ioc_type="yara", value="Emotet_Loader", source_plugin="yarascan", context={}),
    ]
    sent = {}
    fake = MagicMock()
    fake.add_event.side_effect = lambda ev: sent.setdefault("event", ev) and {"Event": {"id": "1"}}
    with patch("orochi.website.ioc.PyMISP", return_value=fake):
        export_iocs_to_misp(dump, iocs)
    # Re-load the event as MISP would: unknown types or categories raise here
    loaded = MISPEvent()
    loaded.load(sent["event"].to_json())
    types = {a.type: a for a in loaded.attributes}
    assert set(types) == {"ip-dst", "sha256", "text"}
    assert "Emotet_Loader" in types["text"].value and types["text"].category == "Artifacts dropped"
