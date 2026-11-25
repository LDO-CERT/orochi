"""Dump states: card actions available in each state and retry by dump index."""

from unittest.mock import patch

import pytest
from django.template.loader import render_to_string
from django.test import RequestFactory

pytestmark = pytest.mark.django_db

ACTIONS = {
    "hubs": "AI Narrative",
    "hex": "Hex View",
    "restart": "Restart Auto Plugin",
    "retry": "Retry Processing",
    "symbols": "Smart Symbol Assistant",
    "download": "Download Dump",
    "error": "View Error",
}

EXPECTED = {
    1: {"hubs", "hex", "download"},  # Processing
    2: set(),  # Unzipping
    3: {"hubs", "hex", "restart", "symbols", "download"},  # Completed (assistant: retry unsatisfied plugins)
    5: {"error", "retry", "download"},  # Error
    6: {"symbols", "hex", "download"},  # Missing Symbols
}


@pytest.mark.parametrize("status", sorted(EXPECTED))
def test_dump_card_offers_only_the_actions_of_its_state(admin, status):
    request = RequestFactory().get("/")
    request.user = admin
    dump = {
        "index": "idx-1",
        "name": "sample",
        "color": "#123456",
        "os": "Linux",
        "status": status,
        "has_auto": True,
        "risk_score": 0,
    }
    html = render_to_string("website/partial_dump_item.html", {"dump": dump}, request=request)
    shown = {key for key, label in ACTIONS.items() if label in html}
    assert shown == EXPECTED[status]


def test_retry_accepts_the_dump_index(client, admin, dump):
    dump.status = 5
    dump.save()
    client.force_login(admin)
    with patch("orochi.website.tasks.manage_upload") as task:
        resp = client.post(f"/api/tasks/dump_{dump.index}/retry")
    assert resp.status_code == 200, resp.content
    task.enqueue.assert_called_once_with(dump.pk)
    dump.refresh_from_db()
    assert dump.status == 1
    assert dump.get_status_display() == "Processing"
