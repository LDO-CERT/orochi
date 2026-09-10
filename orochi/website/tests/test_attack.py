import json

import pytest
from django.urls import reverse

from orochi.website.attack import (
    generate_navigator_layer,
    get_all_technique_choices,
    get_case_attack_coverage,
    get_technique_info,
    parse_technique_ids,
)
from orochi.website.models import Case, Finding

pytestmark = pytest.mark.django_db


def test_parse_technique_ids():
    assert parse_technique_ids("T1055") == ["T1055"]
    assert parse_technique_ids("t1055.001, T1059.003 and t1003") == [
        "T1055.001",
        "T1059.003",
        "T1003",
    ]
    # Duplicates are removed while preserving order
    assert parse_technique_ids("T1055, T1055, T1055.001") == ["T1055", "T1055.001"]
    assert parse_technique_ids("") == []
    assert parse_technique_ids(None) == []


def test_get_technique_info():
    info = get_technique_info("T1055")
    assert info["id"] == "T1055"
    assert info["name"] != ""
    assert "https://attack.mitre.org/techniques/T1055/" == info["url"]
    assert len(info["tactics"]) > 0


def test_get_all_technique_choices():
    choices = get_all_technique_choices()
    assert len(choices) > 50
    assert any(c["id"] == "T1055" for c in choices)


def test_case_attack_coverage_and_navigator_layer(admin):
    case = Case.objects.create(name="APT_Scenario", user=admin)
    Finding.objects.create(
        case=case,
        mitre_attack_technique="T1055",
        severity="Critical",
        note="Process injection observed",
    )
    Finding.objects.create(
        case=case,
        mitre_attack_technique="T1059.001, T1053.005",
        severity="High",
        note="Malicious script in scheduled task",
    )
    Finding.objects.create(
        case=case,
        mitre_attack_technique="",
        severity="Low",
        note="Untagged finding",
    )

    coverage = get_case_attack_coverage(case.findings.all())
    assert coverage["unique_techniques_count"] == 3
    assert coverage["total_tagged_findings"] == 2
    assert len(coverage["active_tactics"]) > 0

    # Test Navigator Layer generation
    layer = generate_navigator_layer(case, case.findings.all())
    assert layer["name"] == "APT_Scenario - ATT&CK Layer"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) == 3

    tech_map = {t["techniqueID"]: t for t in layer["techniques"]}
    assert "T1055" in tech_map
    assert tech_map["T1055"]["score"] == 4
    assert tech_map["T1055"]["color"] == "#dc3545"


def test_case_mitre_export_view(client, admin):
    client.force_login(admin)
    case = Case.objects.create(name="LayerExportCase", user=admin)
    Finding.objects.create(
        case=case,
        mitre_attack_technique="T1055.012",
        severity="Critical",
        note="Process Hollowing",
    )

    url = reverse("website:case_mitre_export", kwargs={"pk": case.pk})
    response = client.get(url)

    assert response.status_code == 200
    assert response["Content-Type"] == "application/json"
    assert "case_layerexportcase_mitre_layer.json" in response["Content-Disposition"]

    layer_data = json.loads(response.content)
    assert layer_data["domain"] == "enterprise-attack"
    assert len(layer_data["techniques"]) == 1
    assert layer_data["techniques"][0]["techniqueID"] == "T1055.012"


def test_case_detail_renders_mitre_coverage(client, admin):
    client.force_login(admin)
    case = Case.objects.create(name="DetailCoverageCase", user=admin)
    Finding.objects.create(
        case=case,
        mitre_attack_technique="T1055",
        severity="High",
        note="Injection test",
    )

    url = reverse("website:case_detail", kwargs={"pk": case.pk})
    response = client.get(url, HTTP_HX_REQUEST="true")

    assert response.status_code == 200
    content = response.content.decode("utf-8")
    assert "MITRE ATT&CK Coverage" in content
    assert "T1055" in content
    assert "Navigator Layer (JSON)" in content
    # Verify Matrix UI components are rendered
    assert "mitre_matrix_view" in content
    assert "Cyber Kill Chain Pipeline" in content
    assert "btn_scope_covered" in content
    assert "btn_scope_full" in content
    assert "mitre_inspector_modal" in content


def test_tactic_normalization_and_catalog():
    from orochi.website.attack import (
        ATTACK_TACTICS,
        get_tactic_catalog,
        normalize_tactic,
    )

    assert normalize_tactic("Stealth") == "Defense Evasion"
    assert normalize_tactic("defense impairment") == "Defense Evasion"
    assert normalize_tactic("Execution") == "Execution"
    assert normalize_tactic("") is None

    catalog = get_tactic_catalog()
    assert len(catalog) == len(ATTACK_TACTICS)
    for tactic in ATTACK_TACTICS:
        assert tactic in catalog
        assert len(catalog[tactic]) > 0
    assert len(catalog["Defense Evasion"]) >= 100


def test_matrix_columns_generation(admin):
    from orochi.website.attack import ATTACK_TACTICS

    case = Case.objects.create(name="MatrixTestScenario", user=admin)
    Finding.objects.create(
        case=case,
        mitre_attack_technique="T1055",  # Defense Evasion, Privilege Escalation
        severity="Critical",
        note="Memory injection detected",
    )
    Finding.objects.create(
        case=case,
        mitre_attack_technique="T1059.001",  # Execution
        severity="Medium",
        note="PowerShell script executed",
    )

    coverage = get_case_attack_coverage(case.findings.all())

    # Matrix metrics
    assert coverage["unique_techniques_count"] == 2
    assert coverage["total_tagged_findings"] == 2
    assert coverage["tactics_covered_count"] >= 2
    assert coverage["coverage_percentage"] > 0
    assert coverage["severity_counts"]["Critical"] == 1
    assert coverage["severity_counts"]["Medium"] == 1
    assert coverage["severity_counts"]["High"] == 0

    # Matrix columns
    columns = coverage["matrix_columns"]
    assert len(columns) == len(ATTACK_TACTICS)
    assert [c["name"] for c in columns] == ATTACK_TACTICS

    # Check Execution column
    exec_col = next(c for c in columns if c["name"] == "Execution")
    assert exec_col["has_detections"] is True
    assert exec_col["detected_count"] >= 1
    assert exec_col["tactic_id"] == "TA0002"
    assert any(t["id"] == "T1059.001" for t in exec_col["detected_techniques"])

    # Check that undetected techniques are represented in all_techniques
    assert len(exec_col["all_techniques"]) > exec_col["detected_count"]
    detected_in_all = [t for t in exec_col["all_techniques"] if t["is_detected"]]
    undetected_in_all = [t for t in exec_col["all_techniques"] if not t["is_detected"]]
    assert len(detected_in_all) >= 1
    assert len(undetected_in_all) > 0
