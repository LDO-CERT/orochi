from unittest.mock import MagicMock, patch

import pytest
import requests
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from orochi.website.defaults import SERVICE_OLLAMA
from orochi.website.models import Case, Finding, ReportTemplate, Service

pytestmark = pytest.mark.django_db


@pytest.fixture
def test_case(admin):
    return Case.objects.create(
        name="Test Incident 2026",
        description="Forensic investigation test case",
        user=admin,
    )


@pytest.fixture
def report_template():
    return ReportTemplate.objects.create(
        name="Standard HTML Incident Report",
        template=SimpleUploadedFile(
            "report.html",
            (
                "<html><body>"
                "<h1>Report: {{ case.name }}</h1>"
                "<div id='summary'>{{ ai_summary|default:'No AI Summary' }}</div>"
                "<ul>"
                "{% for f in findings %}"
                "<li>[{{ f.severity }}] {{ f.mitre_attack_technique }}: {{ f.note }}</li>"
                "{% endfor %}"
                "</ul>"
                "</body></html>"
            ).encode("utf-8"),
        ),
    )


def test_case_report_with_ai_success(client, admin, test_case, report_template):
    """Test generating case report with Ollama AI summary successfully."""
    client.force_login(admin)

    # Setup Ollama service
    Service.objects.create(
        name=SERVICE_OLLAMA,
        url="http://mock-ollama:11434",
        key="mistral:latest",
    )

    # Add findings to case
    Finding.objects.create(
        case=test_case,
        severity="Critical",
        mitre_attack_technique="T1055 - Process Injection",
        note="Malfind detected injected shellcode in explorer.exe (PID 1420)",
    )
    Finding.objects.create(
        case=test_case,
        severity="High",
        mitre_attack_technique="T1071 - C2 Application Layer Protocol",
        note="Outbound connection to unusual IP on port 4444",
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": "Executive Summary: Investigation revealed process injection and C2 beaconing."
    }

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    with patch("requests.post", return_value=mock_response) as mock_post:
        response = client.post(
            report_url,
            {"template_id": report_template.pk, "use_ai": "true"},
        )

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert "Report: Test Incident 2026" in content
        assert "Executive Summary: Investigation revealed process injection" in content
        assert "T1055 - Process Injection" in content

        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        call_json = mock_post.call_args[1]["json"]
        assert call_url == "http://mock-ollama:11434/api/generate"
        assert call_json["model"] == "mistral:latest"
        assert call_json["stream"] is False
        assert "Test Incident 2026" in call_json["prompt"]
        assert "T1055 - Process Injection" in call_json["prompt"]
        assert "Malfind detected injected shellcode" in call_json["prompt"]


def test_case_report_with_ai_default_model(client, admin, test_case, report_template):
    """Test that empty service key defaults to llama3 model."""
    client.force_login(admin)

    Service.objects.create(
        name=SERVICE_OLLAMA,
        url="http://mock-ollama:11434",
        key="",  # empty key
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": "AI Summary generated via llama3"}

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    with patch("requests.post", return_value=mock_response) as mock_post:
        response = client.post(
            report_url,
            {"template_id": report_template.pk, "use_ai": "true"},
        )

        assert response.status_code == 200
        assert mock_post.call_args[1]["json"]["model"] == "llama3"


def test_case_report_ai_ollama_error_status(client, admin, test_case, report_template):
    """Test graceful handling when Ollama returns non-200 HTTP status code."""
    client.force_login(admin)

    Service.objects.create(
        name=SERVICE_OLLAMA,
        url="http://mock-ollama:11434",
        key="llama3",
    )

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error: model llama3 not pulled"

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    with patch("requests.post", return_value=mock_response):
        response = client.post(
            report_url,
            {"template_id": report_template.pk, "use_ai": "true"},
        )

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert (
            "Error from Ollama: Internal Server Error: model llama3 not pulled"
            in content
        )


def test_case_report_ai_connection_exception(client, admin, test_case, report_template):
    """Test graceful handling when requests raises ConnectionError / Timeout."""
    client.force_login(admin)

    Service.objects.create(
        name=SERVICE_OLLAMA,
        url="http://mock-ollama:11434",
        key="llama3",
    )

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    with patch(
        "requests.post",
        side_effect=requests.exceptions.ConnectionError(
            "Connection refused on port 11434"
        ),
    ):
        response = client.post(
            report_url,
            {"template_id": report_template.pk, "use_ai": "true"},
        )

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert "Error connecting to Ollama: Connection refused on port 11434" in content


def test_case_report_without_ai_flag(client, admin, test_case, report_template):
    """Test generating report when use_ai is false: Ollama should NOT be contacted."""
    client.force_login(admin)

    Service.objects.create(
        name=SERVICE_OLLAMA,
        url="http://mock-ollama:11434",
        key="llama3",
    )

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    with patch("requests.post") as mock_post:
        response = client.post(
            report_url,
            {"template_id": report_template.pk, "use_ai": "false"},
        )

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert "No AI Summary" in content
        mock_post.assert_not_called()


def test_case_report_missing_ollama_service(client, admin, test_case, report_template):
    """Test report generation when SERVICE_OLLAMA is not configured in the database."""
    client.force_login(admin)

    # Ensure no Ollama service exists
    Service.objects.filter(name=SERVICE_OLLAMA).delete()

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    with patch("requests.post") as mock_post:
        response = client.post(
            report_url,
            {"template_id": report_template.pk, "use_ai": "true"},
        )

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert "Ollama service is not configured" in content
        mock_post.assert_not_called()


def test_case_report_readonly_user_forbidden(
    client, readonly_user, test_case, report_template
):
    """Test that ReadOnly users cannot generate reports (blocked by is_not_readonly decorator)."""
    client.force_login(readonly_user)

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    response = client.post(
        report_url,
        {"template_id": report_template.pk},
    )
    # user_passes_test redirects to login URL on failure
    assert response.status_code == 302


def test_case_report_collaborator_access(
    client, user, admin, test_case, report_template
):
    """Test that an added collaborator can access and generate the case report."""
    test_case.collaborators.add(user)
    client.force_login(user)

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    response = client.post(
        report_url,
        {"template_id": report_template.pk, "use_ai": "false"},
    )
    assert response.status_code == 200
    assert "Report: Test Incident 2026" in response.content.decode("utf-8")


def test_case_report_unauthorized_user_404(client, user, test_case, report_template):
    """Test that an unauthorized user without access to the case receives 404."""
    client.force_login(user)

    report_url = reverse("website:case_report", kwargs={"pk": test_case.pk})
    response = client.post(
        report_url,
        {"template_id": report_template.pk, "use_ai": "false"},
    )
    assert response.status_code == 404
