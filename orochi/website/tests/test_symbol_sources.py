"""Debug package resolution from Linux banners (#167), without network access."""

from orochi.utils import symbol_sources
from orochi.utils.symbol_sources import get_path_from_banner, parse_banner, resolve_debug_package

DEBIAN_3_2 = (
    "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3 (Debian 4.6.3-14) ) "
    "#1 SMP Debian 3.2.57-3+deb7u2"
)
DEBIAN_4_19 = (
    "Linux version 4.19.0-5-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-7)) "
    "#1 SMP Debian 4.19.37-5 (2019-06-19)"
)
UBUNTU_5_4 = (
    "Linux version 5.4.0-26-generic (buildd@lcy01-amd64-029) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) "
    "#30-Ubuntu SMP Mon Apr 20 16:58:30 UTC 2020 (Ubuntu 5.4.0-26.30-generic 5.4.30)"
)


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    """Answers snapshot.debian.org API calls from ``snapshot`` and HEAD requests from ``existing``."""

    def __init__(self, snapshot=None, existing=()):
        self.snapshot = snapshot or {}
        self.existing = set(existing)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        for key, payload in self.snapshot.items():
            if key in url:
                return FakeResponse(200, payload)
        return FakeResponse(404)

    def head(self, url, **kwargs):
        self.calls.append(("HEAD", url))
        return FakeResponse(200 if url in self.existing else 404)


def test_parse_banner_reads_exact_versions_and_arch():
    assert parse_banner(DEBIAN_3_2).version == "3.2.57-3+deb7u2"
    assert parse_banner(DEBIAN_4_19).version == "4.19.37-5"
    ubuntu = parse_banner(UBUNTU_5_4)
    assert (ubuntu.distro, ubuntu.kernel, ubuntu.version, ubuntu.arch) == (
        "Ubuntu",
        "5.4.0-26-generic",
        "5.4.0-26.30",
        "amd64",
    )
    # Older Ubuntu banners without the trailing "(Ubuntu ...)": version from "#46-Ubuntu"
    old = parse_banner(
        "Linux version 5.4.0-42-generic (buildd@host) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) "
        "#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020"
    )
    assert old.version == "5.4.0-42.46"
    assert (
        parse_banner(
            "Linux version 5.10.0-27-arm64 (x) (gcc version 10 (Debian 10.2.1-6)) #1 SMP Debian 5.10.205-2"
        ).arch
        == "arm64"
    )


def test_debian_uses_snapshot_for_the_exact_build():
    session = FakeSession(
        snapshot={
            "linux-image-3.2.0-4-amd64-dbg/3.2.57-3%2Bdeb7u2/": {
                "result": [{"architecture": "i386", "hash": "bad"}, {"architecture": "amd64", "hash": "37f2"}]
            },
            # A different build of the same kernel must never be chosen
            "linux-image-3.2.0-4-amd64-dbg/3.2.57-3/": {"result": [{"architecture": "amd64", "hash": "wrong"}]},
        }
    )
    _, urls = resolve_debug_package(DEBIAN_3_2, session=session)
    assert urls == ["https://snapshot.debian.org/file/37f2#linux-image-3.2.0-4-amd64-dbg_3.2.57-3+deb7u2_amd64.deb"]
    assert urls[0].endswith(".deb")  # the Downloader picks the package type from the URL


def test_debian_falls_back_to_current_pools():
    pool_url = "https://deb.debian.org/debian/pool/main/l/linux/linux-image-4.19.0-5-amd64-dbg_4.19.37-5_amd64.deb"
    session = FakeSession(existing={pool_url})
    assert resolve_debug_package(DEBIAN_4_19, session=session)[1] == [pool_url]


def test_ubuntu_uses_deterministic_ddeb_names():
    url = (
        "http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/"
        "linux-image-unsigned-5.4.0-26-generic-dbgsym_5.4.0-26.30_amd64.ddeb"
    )
    # A prefix-similar package (5.4.0-2) must not be picked: only exact names are requested
    session = FakeSession(existing={url})
    assert resolve_debug_package(UBUNTU_5_4, session=session)[1] == [url]
    assert all("5.4.0-26-generic" in u for _, u in session.calls)


def test_sentinels_and_network_errors(monkeypatch):
    assert get_path_from_banner("Unknown custom kernel string") == [symbol_sources.PARSE_FAIL]
    fedora = "Linux version 6.5.6-300.fc39.x86_64 (mockbuild@x) (gcc (GCC) 13.2.1) #1 SMP PREEMPT_DYNAMIC Fri Oct  6 19:57:21 UTC 2023"
    assert get_path_from_banner(fedora) == [symbol_sources.UNSUPPORTED]

    class Broken(FakeSession):
        def get(self, url, **kwargs):
            raise symbol_sources.requests.ConnectionError("offline")

        def head(self, url, **kwargs):
            raise symbol_sources.requests.ConnectionError("offline")

    monkeypatch.setattr(symbol_sources.requests, "Session", Broken)
    result = get_path_from_banner(DEBIAN_4_19)
    assert len(result) == 1 and result[0].startswith("[Not found]")
