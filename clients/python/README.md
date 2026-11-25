# Orochi Python Client & CLI (`orochi-client`)

Official Python SDK and CLI for automating memory dump uploads, playbook execution, progress polling, and report/IOC exports against Orochi.

## Build & Install with `uv`

```bash
cd clients/python
uv build
uv pip install .
```

## Quick Start (Python)

```python
from orochi_client import OrochiClient

client = OrochiClient(base_url="https://orochi.local", token="oro_...")
dump = client.upload_dump("memory.raw", name="Workstation-01", operating_system="Windows")
client.launch_playbook("win_malware_quick", dump["index"])
status = client.wait_for_plugin(dump["index"], "windows.pslist.PsList", timeout=600)
report_md = client.export_case_report(case_id=1, fmt="markdown")
```

## Quick Start (CLI)

```bash
export OROCHI_URL="https://orochi.local"
export OROCHI_TOKEN="oro_..."

orochi-cli upload memory.raw --name Workstation-01 --os Windows
orochi-cli playbook run win_malware_quick <dump_index>
orochi-cli status <dump_index> --plugin windows.pslist.PsList
orochi-cli export-report 1 --format markdown -o report.md
```
