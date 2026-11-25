"""Submission helpers for short-lived processes (management commands)."""

from unittest.mock import MagicMock, patch

import pytest

from orochi.backends import dask_client


def test_wait_for_scheduler_polls_until_the_key_is_known():
    client = MagicMock()
    client.run_on_scheduler.side_effect = [False, False, True]
    with patch("time.sleep"):
        assert dask_client.wait_for_scheduler("k1", timeout=10, client=client) is True
    assert client.run_on_scheduler.call_count == 3


def test_wait_for_scheduler_gives_up_after_the_timeout():
    client = MagicMock()
    client.run_on_scheduler.side_effect = RuntimeError("scheduler down")
    assert dask_client.wait_for_scheduler("k1", timeout=0, client=client) is False


def test_submit_and_confirm_returns_the_key_or_raises():
    client = MagicMock()
    client.submit.return_value.key = "manage_upload-1"
    with (
        patch.object(dask_client, "get_dask_client", return_value=client),
        patch("distributed.fire_and_forget") as fire,
        patch.object(dask_client, "wait_for_scheduler", return_value=True),
    ):
        assert dask_client.submit_and_confirm(print, "x") == "manage_upload-1"
    fire.assert_called_once()
    client.submit.assert_called_once_with(print, "x", pure=False)

    with (
        patch.object(dask_client, "get_dask_client", return_value=client),
        patch("distributed.fire_and_forget"),
        patch.object(dask_client, "wait_for_scheduler", return_value=False),
        pytest.raises(RuntimeError),
    ):
        dask_client.submit_and_confirm(print, "x")
