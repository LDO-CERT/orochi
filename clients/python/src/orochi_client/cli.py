"""Command-line interface for Orochi (orochi-cli, Issue #1574)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .client import OrochiClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="orochi-cli", description="Orochi Memory Forensics CLI")
    parser.add_argument("--url", default=os.environ.get("OROCHI_URL", "http://localhost:8000"), help="Orochi base URL")
    parser.add_argument("--token", default=os.environ.get("OROCHI_TOKEN", ""), help="Orochi Bearer API token")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")

    sub = parser.add_subparsers(dest="command", required=True)

    p_up = sub.add_parser("upload", help="Upload a memory dump")
    p_up.add_argument("file", help="Path to memory dump file")
    p_up.add_argument("--name", required=True, help="Dump name")
    p_up.add_argument("--os", default="Windows", choices=["Windows", "Linux", "Mac"], help="Operating system")

    p_st = sub.add_parser("status", help="Inspect dump or plugin status")
    p_st.add_argument("dump_index", help="Dump UUID index")
    p_st.add_argument("--plugin", help="Specific plugin name to poll")

    p_pb = sub.add_parser("playbook", help="List or run auto-triage playbooks")
    pb_sub = p_pb.add_subparsers(dest="pb_action", required=True)
    pb_sub.add_parser("list", help="List playbooks")
    p_pb_run = pb_sub.add_parser("run", help="Launch a playbook on a dump")
    p_pb_run.add_argument("playbook_id", help="Playbook ID")
    p_pb_run.add_argument("dump_index", help="Dump UUID index")

    p_rep = sub.add_parser("export-report", help="Export a case report")
    p_rep.add_argument("case_id", type=int, help="Case ID")
    p_rep.add_argument("--format", default="markdown", choices=["markdown", "html", "pdf", "stix"])
    p_rep.add_argument("-o", "--output", help="Output file path (prints to stdout if omitted)")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    client = OrochiClient(base_url=args.url, token=args.token or None, verify_ssl=not args.insecure)

    if args.command == "upload":
        res = client.upload_dump(args.file, name=args.name, operating_system=args.os)
        print(json.dumps(res, indent=2))
    elif args.command == "status":
        res = (
            client.get_plugin_status(args.dump_index, args.plugin) if args.plugin else client.get_dump(args.dump_index)
        )
        print(json.dumps(res, indent=2))
    elif args.command == "playbook":
        if args.pb_action == "list":
            print(json.dumps(client.list_playbooks(), indent=2))
        else:
            print(json.dumps(client.launch_playbook(args.playbook_id, args.dump_index), indent=2))
    elif args.command == "export-report":
        data = client.export_case_report(args.case_id, fmt=args.format)
        if args.output:
            Path(args.output).write_bytes(data)
            print(f"Saved {len(data)} bytes to {args.output}")
        else:
            sys.stdout.buffer.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
