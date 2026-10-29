from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from asgiref.sync import async_to_sync
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.http import Http404
from django.test import RequestFactory
from django.urls import reverse

import orochi.website.routing
from orochi.backends.dask_client import close_dask_client, get_dask_client
from orochi.website.tasks import manage_upload
from orochi.website.views import download

pytestmark = pytest.mark.django_db


def test_websocket_notify_consumer_unauthenticated_rejected():
    """Unauthenticated WebSocket connections must be closed with code 4401."""

    async def _test():
        app = URLRouter(orochi.website.routing.websocket_urlpatterns)
        communicator = WebsocketCommunicator(app, "/ws/notify/1/")
        communicator.scope["user"] = AnonymousUser()
        connected, close_code = await communicator.connect()
        assert not connected
        assert close_code == 4401
        await communicator.disconnect()

    async_to_sync(_test)()


def test_websocket_notify_consumer_unauthorized_room_rejected(admin, user):
    """Non-staff user attempting to join another user's notify channel is rejected with 4403."""

    async def _test():
        app = URLRouter(orochi.website.routing.websocket_urlpatterns)
        communicator = WebsocketCommunicator(app, f"/ws/notify/{admin.pk}/")
        communicator.scope["user"] = user
        connected, close_code = await communicator.connect()
        assert not connected
        assert close_code == 4403
        await communicator.disconnect()

    async_to_sync(_test)()


def test_websocket_notify_consumer_authorized_join_and_block_broadcast(user):
    """Authenticated user can join their own room, but client message broadcasts are blocked."""

    async def _test():
        app = URLRouter(orochi.website.routing.websocket_urlpatterns)
        communicator = WebsocketCommunicator(app, f"/ws/notify/{user.pk}/")
        communicator.scope["user"] = user
        connected, close_code = await communicator.connect()
        assert connected

        # Sending a message from client should return an error and NOT broadcast
        await communicator.send_json_to({"message": "malicious client broadcast"})
        response = await communicator.receive_json_from()
        assert "error" in response
        assert "disabled" in response["error"].lower()

        await communicator.disconnect()

    async_to_sync(_test)()


def test_download_protected_media_x_accel_header(admin, dump, tmp_path):
    """When X-Accel-Support header is present, view returns X-Accel-Redirect header."""
    factory = RequestFactory()
    # Create sample file inside MEDIA_ROOT
    media_dir = Path(settings.MEDIA_ROOT) / dump.index
    media_dir.mkdir(parents=True, exist_ok=True)
    sample_file = media_dir / "protected_sample.raw"
    sample_file.write_bytes(b"FORENSIC_MEMORY_PAYLOAD_TEST")

    url = f"{reverse('website:download')}?path={sample_file}"
    request = factory.get(url, HTTP_X_ACCEL_SUPPORT="yes")
    request.user = admin

    response = download(request)
    assert response.status_code == 200
    assert "X-Accel-Redirect" in response
    assert f"/protected_media/{dump.index}/protected_sample.raw" in response["X-Accel-Redirect"]
    assert "protected_sample.raw" in response["Content-Disposition"]


def test_download_path_traversal_blocked(admin, dump):
    """Attempts to use directory traversal are blocked with 404."""
    factory = RequestFactory()
    url = f"{reverse('website:download')}?path=/media/{dump.index}/../../../etc/passwd"
    request = factory.get(url)
    request.user = admin

    with pytest.raises(Http404):
        download(request)


def test_dask_client_singleton():
    """get_dask_client returns a persistent singleton and handles re-connections."""
    close_dask_client()
    with patch("orochi.backends.dask_client.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.status = "running"
        mock_instance.cluster = None
        mock_client_cls.return_value = mock_instance

        c1 = get_dask_client()
        c2 = get_dask_client()
        assert c1 is c2
        assert mock_client_cls.call_count == 1

        # Simulate closed client
        mock_instance.status = "closed"
        mock_instance2 = MagicMock()
        mock_instance2.status = "running"
        mock_instance2.cluster = None
        mock_client_cls.return_value = mock_instance2

        c3 = get_dask_client()
        assert c3 is mock_instance2
        assert mock_client_cls.call_count == 2
    close_dask_client()


def test_manage_upload_task_is_enqueued(admin, dump):
    """manage_upload task in tasks.py exists and can be queued."""
    assert hasattr(manage_upload, "enqueue")
    with patch("orochi.utils.volatility_dask_elk.manage_upload") as mock_mu:
        manage_upload.call(dump.pk, admin.pk)
        mock_mu.assert_called_once_with(dump_pk=dump.pk, user_pk=admin.pk, password=None, restart=None, move=False)
