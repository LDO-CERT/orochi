import os
from unittest.mock import MagicMock, patch

import pytest

from orochi.utils.timeliner import clean_bodywork, parse_body_line
from orochi.utils.volatility_dask_elk import (
    file_handler_class_factory,
    get_parameters,
    get_path_from_banner,
    save_result_status,
)
from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Dump, Plugin, Result

pytestmark = pytest.mark.django_db


# ==========================================
# Timeliner tests
# ==========================================
def test_parse_body_line_standard():
    line = "pslist - Process 1234 (bash)|0|0|0|0|0|0|1600000000"
    res = parse_body_line(line)
    assert res["Plugin"] == "pslist"
    assert res["Description"] == "Process 1234 (bash)"
    assert res["Date"] is not None
    assert res["Date"].year == 2020


def test_parse_body_line_no_hyphen():
    line = "GenericEventDescription|0|0|0|0|0|0|1600000000"
    res = parse_body_line(line)
    assert res["Plugin"] == "Unknown"
    assert res["Description"] == "GenericEventDescription"
    assert res["Date"] is not None


def test_parse_body_line_invalid_timestamp():
    line = "pslist - Process 1234|0|0|0|0|0|0|invalid_ts"
    res = parse_body_line(line)
    assert res["Plugin"] == "pslist"
    assert res["Date"] is None


def test_parse_body_line_zero_or_negative_timestamp():
    line = "pslist - Process 1234|0|0|0|0|0|0|0"
    res = parse_body_line(line)
    assert res["Date"] is None

    line_neg = "pslist - Process 1234|0|0|0|0|0|0|-100"
    res_neg = parse_body_line(line_neg)
    assert res_neg["Date"] is None


def test_clean_bodywork_generates_html(tmp_path):
    body_file = tmp_path / "body.txt"
    lines = [
        "pslist - bash (PID 100)|0|0|0|0|0|0|1600000000\n",
        "netscan - TCP 127.0.0.1:80|0|0|0|0|0|0|1600000050\n",
        "malfind - Injected shellcode|0|0|0|0|0|0|1600000100\n",
        "\n",  # empty line
        "invalid - Corrupt entry|0|0|0|0|0|0|not_a_ts\n",  # invalid date should be skipped
    ]
    body_file.write_text("".join(lines))

    html = clean_bodywork(str(body_file))
    assert isinstance(html, str)
    assert "plotly" in html.lower() or "div" in html.lower()
    assert "Activity Spikes" in html or "Activity Density" in html


def test_clean_bodywork_with_values():
    values = [
        {
            "Plugin": "PsList",
            "Description": "Process 1 (systemd)",
            "Created Date": "2021-03-03T13:34:47+00:00",
        },
        {
            "Plugin": "Bash",
            "Description": "bash history command",
            "Modified Date": "2021-03-03T14:00:00+00:00",
        },
        {
            "Plugin": "Files",
            "Description": "Cached Inode /etc/passwd",
            "Accessed Date": "2021-03-03T14:30:00+00:00",
        },
    ]
    html = clean_bodywork(values=values)
    assert isinstance(html, str)
    assert "plotly" in html.lower() or "div" in html.lower()
    assert "Interactive Event Timeline" in html


def test_clean_bodywork_empty():
    assert clean_bodywork() == ""
    assert clean_bodywork(values=[]) == ""


def test_parse_body_line_sleuthkit_v3_fallback():
    # Bodyfile v3 line where crtime (parts[-1]) is 0, but mtime (parts[-3]) is a valid epoch
    line = "|Lsof - Process systemd (1/1) Open '/dev/null'|0|0|0|0|0|1614778493|1614778493|1614778493|0\n"
    res = parse_body_line(line)
    assert res["Plugin"] == "Lsof"
    assert res["Date"] is not None
    assert res["Date"].year == 2021


# ==========================================
# Volatility / Dask / Elk utility tests
# ==========================================
def test_file_handler_class_factory_null():
    handler_cls = file_handler_class_factory(output_dir=None, file_list=[])
    assert handler_cls.__name__ == "NullFileHandler"


def test_file_handler_class_factory_lifecycle(tmp_path):
    file_list = []
    handler_cls = file_handler_class_factory(output_dir=str(tmp_path), file_list=file_list)
    assert handler_cls.__name__ == "OrochiFileHandler"

    handler = handler_cls("extracted_artifact.bin")
    assert not handler.closed
    assert handler.mode in ("w+b", "rb+", "wb+")
    assert os.path.exists(handler._name)

    # Write and getvalue
    handler.write(b"SAMPLE DUMP DATA")
    handler.flush()
    assert handler.getvalue() == b"SAMPLE DUMP DATA"

    # Close commits to file_list
    handler.close()
    assert handler.closed
    assert handler in file_list

    # Delete cleans up file
    temp_path = handler._name
    handler.delete()
    assert not os.path.exists(temp_path)


def test_get_path_from_banner_unrecognized():
    res = get_path_from_banner("Unknown custom kernel string")
    assert res == ["[Banner parse fail] insert here symbols url!"]


def test_get_path_from_banner_unsupported_arch():
    banner = "Linux version 5.4.0-42-generic (buildd@host) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 mips"
    res = get_path_from_banner(banner)
    assert res == ["[OS wip] insert here symbols url!"]


@patch("orochi.utils.volatility_dask_elk.requests.get")
def test_get_path_from_banner_ubuntu_success(mock_get):
    banner = "Linux version 5.4.0-42-generic (buildd@lcy02-amd64-082) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 (amd64)"
    mock_resp = MagicMock()
    mock_resp.text = """
    <html>
      <body>
        <a href="linux-image-5.4.0-42-generic_5.4.0-42.46_amd64.ddeb">Download</a>
      </body>
    </html>
    """
    mock_get.return_value = mock_resp

    res = get_path_from_banner(banner)
    assert len(res) == 1
    assert "linux-image-5.4.0-42-generic_5.4.0-42.46_amd64.ddeb" in res[0]


@patch("orochi.utils.volatility_dask_elk.requests.get")
def test_get_path_from_banner_debian_success(mock_get):
    banner = "Linux version 4.19.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.67-2 (2019-08-28)"
    mock_resp = MagicMock()
    mock_resp.text = """
    <html>
      <body>
        <a href="linux-image-4.19.0-6-amd64-dbg_4.19.67-2_amd64.deb">Debian DBG</a>
      </body>
    </html>
    """
    mock_get.return_value = mock_resp

    res = get_path_from_banner(banner)
    assert len(res) == 1
    assert "linux-image-4.19.0-6-amd64-dbg_4.19.67-2_amd64.deb" in res[0]


def test_save_result_status(admin):
    dump = Dump.objects.create(name="UtilityDump", author=admin, index="util_idx")
    plugin, _ = Plugin.objects.get_or_create(name="linux.bash.Bash", defaults={"operating_system": "Linux"})
    result = Result.objects.create(dump=dump, plugin=plugin)

    save_result_status(
        result=result,
        status=RESULT_STATUS_SUCCESS,
        description="Done successfully",
        message="Finished bash plugin analysis",
    )
    result.refresh_from_db()
    assert result.result == RESULT_STATUS_SUCCESS
    assert result.description == "Done successfully"


def test_get_parameters_for_plugin():
    # Test volatility plugin introspection for common plugins
    params = get_parameters("windows.pslist.PsList")
    assert isinstance(params, list)
    # Check structure of returned parameter dictionaries
    for p in params:
        assert "name" in p
        assert "mode" in p
        assert "type" in p
