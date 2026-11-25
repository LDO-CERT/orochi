"""HTTP client for the Orochi REST API (Issue #1574)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests


class OrochiAPIError(RuntimeError):
    """Raised when the Orochi API returns an unexpected HTTP status."""

    def __init__(self, status_code: int, message: str):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code


class OrochiClient:
    """Automation client for uploading dumps, running playbooks, polling progress, and exporting reports."""

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        verify_ssl: bool = True,
        timeout: int = 60,
        session: requests.Session | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = session or requests.Session()
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        resp = self.session.request(method, url, **kwargs)
        if resp.status_code >= 400:
            raise OrochiAPIError(resp.status_code, resp.text[:500])
        return resp

    def upload_dump(
        self,
        file_path: str | Path,
        *,
        name: str,
        operating_system: str = "Windows",
        comment: str = "",
    ) -> dict[str, Any]:
        """Upload a memory image to POST /api/dumps/."""
        path = Path(file_path)
        payload = json.dumps(
            {
                "name": name,
                "operating_system": operating_system,
                "comment": comment,
            }
        )
        with path.open("rb") as fh:
            resp = self._request(
                "POST",
                "/api/dumps/",
                data={"payload": payload},
                files={"upload": (path.name, fh, "application/octet-stream")},
            )
        return resp.json()

    def get_dump(self, dump_index: str) -> dict[str, Any]:
        """Fetch dump details including processing status and symbol_status."""
        return self._request("GET", f"/api/dumps/{dump_index}").json()

    def update_dump(self, dump_index: str, **fields: Any) -> dict[str, Any]:
        """PATCH /api/dumps/{dump_index} metadata (name, comment, color, status, operating_system)."""
        return self._request("PATCH", f"/api/dumps/{dump_index}", json=fields).json()

    def list_dump_plugins(self, dump_index: str) -> list[dict[str, Any]]:
        """List plugins with per-plugin result state and stored row counts."""
        return self._request("GET", f"/api/dumps/{dump_index}/plugins").json()

    def get_plugin_status(self, dump_index: str, plugin_name: str) -> list[dict[str, Any]]:
        """Poll the execution state and row count of one plugin on a dump."""
        return self._request("GET", f"/api/dumps/{dump_index}/plugin/{plugin_name}").json()

    def wait_for_plugin(
        self,
        dump_index: str,
        plugin_name: str,
        *,
        poll_interval: float = 2.0,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        """Poll until a plugin reaches a terminal state (Success/Empty/Error/Unsatisfied)."""
        terminal_codes = {2, 3, 4, 5, 6}
        deadline = time.monotonic() + timeout
        while True:
            items = self.get_plugin_status(dump_index, plugin_name)
            if items and items[0].get("result") in terminal_codes:
                return items[0]
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for {plugin_name} on dump {dump_index}")
            time.sleep(poll_interval)

    def list_playbooks(self, operating_system: str | None = None) -> list[dict[str, Any]]:
        """List available auto-triage playbooks."""
        params = {"os": operating_system} if operating_system else None
        return self._request("GET", "/api/playbooks/", params=params).json()

    def launch_playbook(self, playbook_id: str, dump_index: str) -> dict[str, Any]:
        """Launch a playbook on a dump."""
        return self._request("POST", f"/api/playbooks/{playbook_id}/launch/{dump_index}").json()

    def get_playbook_status(self, playbook_id: str, dump_index: str) -> dict[str, Any]:
        """Get aggregated per-plugin status of a playbook on a dump."""
        return self._request("GET", f"/api/playbooks/{playbook_id}/status/{dump_index}").json()

    def export_case_report(self, case_id: int, fmt: str = "markdown") -> bytes:
        """Download a case report (markdown, html, pdf, stix)."""
        resp = self._request("GET", f"/api/cases/{case_id}/export", params={"format": fmt})
        return resp.content

    def export_case_bundle(self, case_id: int) -> bytes:
        """Download a portable .orochi.zip Case Bundle."""
        return self._request("GET", f"/api/cases/{case_id}/bundle").content

    def import_case_bundle(self, bundle_path: str | Path, *, name: str | None = None) -> dict[str, Any]:
        """Import a .orochi.zip Case Bundle."""
        path = Path(bundle_path)
        params = {"name": name} if name else None
        with path.open("rb") as fh:
            resp = self._request(
                "POST",
                "/api/cases/import-bundle",
                params=params,
                files={"bundle": (path.name, fh, "application/zip")},
            )
        return resp.json()
