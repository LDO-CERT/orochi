"""Automatic Linux symbol resolution after upload (#167) and its user notifications."""

from unittest.mock import MagicMock, patch

import pytest

from orochi.utils.volatility_dask_elk import handle_missing_symbols, mark_automatic_plugins
from orochi.website.defaults import RESULT_STATUS_DISABLED, RESULT_STATUS_NOT_STARTED, RESULT_STATUS_RUNNING
from orochi.website.models import Plugin, Result, UserPlugin
from orochi.website.symbols_assistant import notify_symbols
from orochi.website.tasks import download_symbols_task

pytestmark = pytest.mark.django_db

BANNER = (
    "Linux version 4.19.0-5-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-7)) "
    "#1 SMP Debian 4.19.37-5 (2019-06-19)"
)
URL = "https://snapshot.debian.org/file/ba57#linux-image-4.19.0-5-amd64-dbg_4.19.37-5_amd64.deb"


@pytest.fixture
def linux_dump(dump):
    dump.banner = BANNER
    dump.suggested_symbols_path = [URL]
    dump.save()
    return dump


def _setting(value):
    return patch("extra_settings.models.Setting.get", side_effect=lambda name, default=None: value)


def test_missing_symbols_only_notifies_when_auto_resolve_is_off(linux_dump, admin):
    with (
        _setting(False),
        patch("orochi.website.symbols_assistant.notify_symbols") as notify,
        patch("orochi.website.tasks.download_symbols_task") as task,
    ):
        handle_missing_symbols(linux_dump, admin.pk, {"kernel": "4.19.0-5-amd64"})
    task.enqueue.assert_not_called()
    message = notify.call_args.args[1]
    assert "4.19.0-5-amd64" in message and "AUTO_RESOLVE_SYMBOLS" in message


def test_missing_symbols_start_the_build_when_auto_resolve_is_on(linux_dump, admin):
    with (
        _setting(True),
        patch("orochi.website.symbols_assistant.notify_symbols") as notify,
        patch("orochi.website.tasks.download_symbols_task") as task,
    ):
        handle_missing_symbols(linux_dump, admin.pk, {"kernel": "4.19.0-5-amd64"})
    task.enqueue.assert_called_once_with(url_list=[URL], dump_pk=linux_dump.pk, user_pk=admin.pk, run_automatic=True)
    assert "linux-image-4.19.0-5-amd64-dbg_4.19.37-5_amd64.deb" in notify.call_args.args[1]


@pytest.mark.parametrize(
    ("banner", "suggested", "expected"),
    [
        ("", [], "no Linux kernel banner"),
        (BANNER, ["[Not found] no debug package for kernel 4.19.0-5-amd64"], "[Not found]"),
    ],
)
def test_missing_symbols_explains_why_nothing_can_be_built(dump, admin, banner, suggested, expected):
    dump.banner = banner
    dump.suggested_symbols_path = suggested
    dump.save()
    with (
        _setting(True),
        patch("orochi.website.symbols_assistant.notify_symbols") as notify,
        patch("orochi.website.tasks.download_symbols_task") as task,
    ):
        handle_missing_symbols(dump, admin.pk, {})
    task.enqueue.assert_not_called()
    assert expected in notify.call_args.args[1]


def test_mark_automatic_plugins_restores_the_automatic_selection(linux_dump, admin):
    auto = Plugin.objects.create(name="linux.pslist.PsList", operating_system="Linux")
    manual = Plugin.objects.create(name="linux.bash.Bash", operating_system="Linux")
    UserPlugin.objects.update_or_create(user=admin, plugin=auto, defaults={"automatic": True})
    UserPlugin.objects.update_or_create(user=admin, plugin=manual, defaults={"automatic": False})
    for plugin in (auto, manual):
        Result.objects.create(dump=linux_dump, plugin=plugin, result=RESULT_STATUS_DISABLED)

    assert mark_automatic_plugins(linux_dump, admin.pk) == 1
    assert Result.objects.get(dump=linux_dump, plugin=auto).result == RESULT_STATUS_RUNNING
    assert Result.objects.get(dump=linux_dump, plugin=manual).result == RESULT_STATUS_NOT_STARTED


def test_download_task_runs_automatic_plugins_after_a_successful_build(linux_dump, admin):
    plugin = Plugin.objects.create(name="linux.pslist.PsList", operating_system="Linux")
    UserPlugin.objects.update_or_create(user=admin, plugin=plugin, defaults={"automatic": True})
    Result.objects.create(dump=linux_dump, plugin=plugin, result=RESULT_STATUS_DISABLED)
    messages = []
    downloader = MagicMock()

    def fake_downloader(*args, progress=None, **kwargs):
        progress("Downloading linux-image-4.19.0-5-amd64-dbg_4.19.37-5_amd64.deb (682 MB)...")
        return downloader

    with (
        patch("orochi.utils.download_symbols.Downloader", side_effect=fake_downloader),
        patch("orochi.utils.volatility_dask_elk.check_runnable", return_value=True),
        patch("orochi.utils.volatility_dask_elk.refresh_symbols"),
        patch("orochi.website.symbols_assistant.distribute_symbols_to_workers"),
        patch("orochi.website.symbols_assistant.ensure_symbol_environment"),
        patch("orochi.website.symbols_assistant.notify_symbols", side_effect=lambda d, m, u=None: messages.append(m)),
        patch("orochi.utils.volatility_dask_elk.dispatch_automatic_plugins") as dispatch,
        patch("orochi.website.tasks._send_task_notification") as final,
    ):
        download_symbols_task.call(url_list=[URL], dump_pk=linux_dump.pk, user_pk=admin.pk, run_automatic=True)

    downloader.download_list.assert_called_once()
    dispatch.assert_called_once()
    assert any("682 MB" in m for m in messages)
    assert "Running 1 automatic plugin(s)" in final.call_args.args[2]
    assert Result.objects.get(dump=linux_dump, plugin=plugin).result == RESULT_STATUS_RUNNING


def test_notify_symbols_escapes_dump_and_kernel_strings(dump, admin):
    dump.name = "<img src=x onerror=alert(1)>"
    layer = MagicMock()
    with (
        patch("orochi.website.notifier.get_channel_layer", return_value=layer),
        patch("orochi.website.notifier.async_to_sync", side_effect=lambda fn: fn),
    ):
        notify_symbols(dump, "kernel <script>", admin)
    text = layer.group_send.call_args.args[1]["message"]
    assert "<img" not in text and "<script>" not in text
    assert "&lt;img" in text and "&lt;script&gt;" in text
