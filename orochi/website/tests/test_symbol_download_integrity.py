"""Downloaded symbol packages are checked against the hash their source publishes (#1674 FR-6)."""

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from orochi.utils.download_symbols import Downloader, package_name_from_url, published_hash

PAYLOAD = b"!<arch>\nfake debian package"
SHA1 = hashlib.sha1(PAYLOAD, usedforsecurity=False).hexdigest()
SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


def _response(body: bytes):
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.headers = {"content-length": str(len(body))}
    resp.iter_content.return_value = [body]
    return resp


def _downloader(tmp_path, urls):
    with patch("orochi.utils.download_symbols.Setting.get", return_value=str(tmp_path)):
        return Downloader(url_list=urls)


def test_published_hash_sources():
    assert published_hash(f"https://snapshot.debian.org/file/{SHA1}#linux.deb") == ("sha1", SHA1)
    assert published_hash(f"https://deb.debian.org/pool/linux.deb#linux.deb&sha256={SHA256}") == ("sha256", SHA256)
    assert published_hash("http://ddebs.ubuntu.com/pool/linux.ddeb") is None
    assert package_name_from_url(f"https://x/file/{SHA1}#linux.deb&sha256={SHA256}") == "linux.deb"


@pytest.mark.parametrize(
    "url",
    [
        f"https://snapshot.debian.org/file/{SHA1}#linux.deb",
        f"https://deb.debian.org/linux.deb#linux.deb&sha256={SHA256}",
    ],
)
def test_matching_package_is_accepted_and_recorded(tmp_path, url):
    d = _downloader(tmp_path, [url])
    with (
        patch("orochi.utils.download_symbols.requests.get", return_value=_response(PAYLOAD)),
        patch.object(Downloader, "process_deb", return_value={}) as unpack,
        patch.object(Downloader, "process"),
    ):
        d.download_list()
    unpack.assert_called_once()
    assert d.downloads[url]["sha256"] == SHA256 and d.downloads[url]["verified"]


def test_package_with_a_different_hash_is_refused_before_unpacking(tmp_path):
    url = f"https://snapshot.debian.org/file/{'0' * 40}#linux.deb"
    d = _downloader(tmp_path, [url])
    with (
        patch("orochi.utils.download_symbols.requests.get", return_value=_response(PAYLOAD)),
        patch.object(Downloader, "process_deb") as unpack,
        pytest.raises(ValueError, match="download refused"),
    ):
        d.download_list()
    unpack.assert_not_called()


def test_source_without_published_hash_is_recorded_unverified(tmp_path):
    url = "http://ddebs.ubuntu.com/pool/main/l/linux/linux-image-5.4.0-26-generic-dbgsym_5.4.0-26.30_amd64.ddeb"
    d = _downloader(tmp_path, [url])
    with (
        patch("orochi.utils.download_symbols.requests.get", return_value=_response(PAYLOAD)),
        patch.object(Downloader, "process_ddeb", return_value={}),
        patch.object(Downloader, "process"),
    ):
        d.download_list()
    assert d.downloads[url] == {"name": url.rsplit("/", 1)[1], "sha256": SHA256, "verified": None}


@pytest.mark.django_db
def test_plugin_install_refuses_an_archive_with_another_hash(client, admin):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("plugin.py", "x = 1")
    body = buf.getvalue()
    client.force_login(admin)
    payload = {"plugin_url": "https://github.com/x/plugin.zip", "operating_system": "Windows", "async_mode": False}
    with (
        patch("orochi.api.routers.plugins.validate_public_https_url", side_effect=lambda u: u),
        patch("orochi.api.routers.plugins.requests.get", return_value=MagicMock(ok=True, content=body)),
        patch("orochi.api.routers.plugins.process_plugin_installation", return_value=["custom.plugin"]) as install,
    ):
        bad = client.post("/api/plugins/install", {**payload, "sha256": "0" * 64}, content_type="application/json")
        good = client.post(
            "/api/plugins/install",
            {**payload, "sha256": hashlib.sha256(body).hexdigest()},
            content_type="application/json",
        )
    assert bad.status_code == 400 and "does not match" in bad.json()["errors"]
    assert good.status_code == 200 and "verified" in good.json()["message"]
    install.assert_called_once()
