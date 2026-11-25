"""Resolve the debug package of a Linux kernel banner to download URLs (#167).

Only the exact build of the banner is accepted: a debug package of another build produces an ISF whose banner does not
match the dump, so Volatility would still refuse it.

- Debian: ``linux-image-<kernel>-dbg`` at the version written after ``Debian`` in the banner, looked up in the
  official archive ``snapshot.debian.org`` (every version ever published), then in the current pools.
- Ubuntu: ``linux-image[-unsigned]-<kernel>-dbgsym`` at the version of the banner (``5.4.0-26.30``) on
  ``ddebs.ubuntu.com``, then on Launchpad.

Every candidate is checked with a HEAD request: the result only contains URLs that exist.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from urllib.parse import quote

import requests

from orochi.website.defaults import BANNER_REGEX

logger = logging.getLogger(__name__)

TIMEOUT = 10
SNAPSHOT_API = "https://snapshot.debian.org/mr/binary/{package}/{version}/binfiles"
SNAPSHOT_FILE = "https://snapshot.debian.org/file/{hash}#{filename}"
DEBIAN_POOLS = (
    "https://deb.debian.org/debian/pool/main/l/linux/",
    "https://security.debian.org/debian-security/pool/updates/main/l/linux/",
)
UBUNTU_DDEBS = "http://ddebs.ubuntu.com/ubuntu/pool/main/l/{source}/"
LAUNCHPAD_FILES = "https://launchpad.net/ubuntu/+archive/primary/+files/"

# Sentinels kept compatible with existing callers, which skip entries starting with "["
PARSE_FAIL = "[Banner parse fail] insert here symbols url!"
UNSUPPORTED = "[OS wip] insert here symbols url!"
NOT_FOUND = "[Not found] no debug package for kernel {kernel} ({distro} {version})"


@dataclass(frozen=True)
class KernelInfo:
    """Kernel identity parsed from a Linux banner."""

    distro: str
    kernel: str
    version: str | None
    arch: str


def _proxies() -> dict[str, str] | None:
    """Proxies from ``http_proxy`` / ``https_proxy``, as used by the symbol Downloader."""
    if os.environ.get("http_proxy") or os.environ.get("https_proxy"):
        return {"http": os.environ.get("http_proxy"), "https": os.environ.get("https_proxy")}
    return None


def _arch(kernel: str, banner: str) -> str:
    """Debian/Ubuntu architecture from the kernel flavour, falling back to markers in the banner, then amd64."""
    flavour = kernel.lower()
    if flavour.endswith(("-amd64", "-cloud-amd64", "-rt-amd64")):
        return "amd64"
    if flavour.endswith(("-arm64", "-rt-arm64")):
        return "arm64"
    if re.search(r"-686(-pae)?$|-486$", flavour):
        return "i386"
    if flavour.endswith(("-armmp", "-armmp-lpae")):
        return "armhf"
    lowered = banner.lower()
    if "aarch64" in lowered or "arm64" in lowered:
        return "arm64"
    if "i686" in lowered or "i386" in lowered:
        return "i386"
    return "amd64"


def parse_banner(banner: str) -> KernelInfo | None:
    """Parse distro, kernel release, exact package version and architecture from a Linux banner."""
    match = re.match(BANNER_REGEX, (banner or "").strip())
    if not match:
        return None
    kernel = match["kernel"]
    info = match["info"] or ""
    gcc = (match["gcc"] or "").lower()
    lowered = f"{gcc} {info.lower()}"

    if "ubuntu" in lowered:
        version = None
        if m := re.search(r"\(Ubuntu (\S+?)-[a-z][\w-]* \d", info):
            version = m.group(1)
        elif (m := re.match(r"(\d+\.\d+\.\d+-\d+)", kernel)) and info.startswith("-Ubuntu"):
            # "#46-Ubuntu": the regex puts 46 in the "number" group
            version = f"{m.group(1)}.{match['number']}"
        return KernelInfo("Ubuntu", kernel, version, _arch(kernel, banner))

    if "debian" in lowered:
        version = m.group(1) if (m := re.search(r"Debian (\d[\w.~+:-]*)", info)) else None
        return KernelInfo("Debian", kernel, version, _arch(kernel, banner))

    return KernelInfo("Unknown", kernel, None, _arch(kernel, banner))


def _exists(session: requests.Session, url: str) -> bool:
    try:
        resp = session.head(url, allow_redirects=True, timeout=TIMEOUT, proxies=_proxies())
    except requests.RequestException as exc:
        logger.debug("HEAD %s failed: %s", url, exc)
        return False
    return resp.status_code == 200


def _debian_candidates(session: requests.Session, info: KernelInfo) -> list[str]:
    package = f"linux-image-{info.kernel}-dbg"
    # File names never carry the version epoch ("1:4.19..." -> "4.19...")
    filename = f"{package}_{re.sub(r'^\d+:', '', info.version)}_{info.arch}.deb"
    try:
        resp = session.get(
            SNAPSHOT_API.format(package=quote(package), version=quote(info.version, safe="")),
            timeout=TIMEOUT,
            proxies=_proxies(),
        )
        if resp.status_code == 200:
            for item in resp.json().get("result", []):
                if item.get("architecture") == info.arch and item.get("hash"):
                    return [SNAPSHOT_FILE.format(hash=item["hash"], filename=filename)]
    except (requests.RequestException, ValueError) as exc:
        logger.info("snapshot.debian.org lookup failed for %s %s: %s", package, info.version, exc)
    return [url for base in DEBIAN_POOLS if _exists(session, url := f"{base}{filename}")][:1]


def _ubuntu_candidates(session: requests.Session, info: KernelInfo) -> list[str]:
    names = [
        f"linux-image-unsigned-{info.kernel}-dbgsym_{info.version}_{info.arch}.ddeb",
        f"linux-image-{info.kernel}-dbgsym_{info.version}_{info.arch}.ddeb",
    ]
    sources = ["linux"]
    if m := re.match(r"(\d+)\.(\d+)", info.kernel):
        sources.append(f"linux-hwe-{m.group(1)}.{m.group(2)}")
    for source in sources:
        for name in names:
            if _exists(session, url := f"{UBUNTU_DDEBS.format(source=source)}{name}"):
                return [url]
    for name in names:
        if _exists(session, url := f"{LAUNCHPAD_FILES}{name}"):
            return [url]
    return []


def resolve_debug_package(banner: str, session: requests.Session | None = None) -> tuple[KernelInfo | None, list[str]]:
    """Return the parsed kernel and the URLs of its exact debug package (empty when none was found)."""
    info = parse_banner(banner)
    if info is None or info.version is None or info.distro not in ("Debian", "Ubuntu"):
        return info, []
    session = session or requests.Session()
    if info.distro == "Debian":
        return info, _debian_candidates(session, info)
    return info, _ubuntu_candidates(session, info)


def get_path_from_banner(banner: str) -> list[str]:
    """Find the debug package URL for a banner; a single ``[...]`` sentinel describes why none was found."""
    info, urls = resolve_debug_package(banner)
    if info is None:
        return [PARSE_FAIL]
    if info.distro not in ("Debian", "Ubuntu") or info.version is None:
        return [UNSUPPORTED]
    return urls or [NOT_FOUND.format(kernel=info.kernel, distro=info.distro, version=info.version)]
