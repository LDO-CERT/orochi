"""Forms posted from inside the shared modal must close it on success ("Add Dossier to Case")."""

from pathlib import Path

import pytest
from django.conf import settings
from django.urls import reverse

UI_JS = Path(settings.APPS_DIR) / "static" / "js" / "orochi_ui.js"


def test_loading_spinner_does_not_replace_a_form_posting_from_inside_the_modal():
    """The spinner used to detach the submitting form, so htmx fired HX-Trigger (closeModal) on a removed node."""
    js = UI_JS.read_text()
    handler = js[js.index('"htmx:beforeRequest"') :][:600]
    assert "evt.detail.target.contains(evt.detail.elt)) return;" in handler
    assert handler.index("contains(evt.detail.elt)") < handler.index("innerHTML")


@pytest.mark.django_db
def test_standalone_dossier_page_has_the_modal_for_add_to_case(client, admin, dump):
    client.force_login(admin)
    resp = client.get(reverse("website:dump_process_dossier", kwargs={"index": dump.index, "pid": 4}))
    html = resp.content.decode()
    assert resp.status_code == 200
    assert 'id="modal-update"' in html and 'id="orochi-modal-content"' in html
    assert "Add Dossier to Case" in html


def test_hx_confirm_uses_the_app_dialog_not_window_confirm():
    """Delete case/evidence/finding etc. (hx-confirm) ask through SweetAlert, then issue the request."""
    js = UI_JS.read_text()
    handler = js[js.index('"htmx:confirm"') :][:1200]
    assert "evt.preventDefault()" in handler and "Swal.fire" in handler
    assert "evt.detail.issueRequest(true)" in handler
