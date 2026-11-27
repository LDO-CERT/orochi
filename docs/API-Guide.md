# Orochi API Guide

_Comprehensive REST API and Developer Integration Reference_

---

## Table of Contents

- [Orochi API Guide](#orochi-api-guide)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Authentication](#authentication)
    - [Session Authentication](#session-authentication)
    - [Personal API Tokens (Bearer)](#personal-api-tokens-bearer)
  - [Interactive API Documentation (Swagger \& ReDoc)](#interactive-api-documentation-swagger--redoc)
  - [API Endpoints Reference](#api-endpoints-reference)
    - [0. Authentication \& Tokens API (`/api/auth/`)](#0-authentication--tokens-api-apiauth)
      - [Create Personal API Token](#create-personal-api-token)
    - [1. Folders API (`/api/folders/`)](#1-folders-api-apifolders)
    - [2. Hosts API (`/api/hosts/`)](#2-hosts-api-apihosts)
    - [3. Dumps API (`/api/dumps/`)](#3-dumps-api-apidumps)
      - [Flexible Folder \& Host Association](#flexible-folder--host-association)
      - [Secrets \& Credentials Extraction](#secrets--credentials-extraction)
      - [Forensic Behavioral Triage \& Risk Evaluation](#forensic-behavioral-triage--risk-evaluation)
      - [Interactive Process Tree Visualization](#interactive-process-tree-visualization)
      - [Threat Intelligence \& IOC Extraction Hub](#threat-intelligence--ioc-extraction-hub)
      - [Forensic Timeline Stream API](#forensic-timeline-stream-api)
      - [Finding Promotion](#finding-promotion)
      - [Plugin Row Annotations](#plugin-row-annotations)
      - [AI First-Pass Forensic Triage Narrative](#ai-first-pass-forensic-triage-narrative)
      - [Sandbox Submission (CAPE / Cuckoo)](#sandbox-submission-cape--cuckoo)
    - [4. Cases API (`/api/cases/`)](#4-cases-api-apicases)
      - [Cross-Dump Multi-Host Forensic Graph](#cross-dump-multi-host-forensic-graph)
      - [Unified Case Timeline Stream](#unified-case-timeline-stream)
      - [Collaborative Case Notes](#collaborative-case-notes)
      - [Multi-Format Case Report Export](#multi-format-case-report-export)
      - [Real-Time Case Presence WebSocket](#real-time-case-presence-websocket)
      - [External Integrations: SIEM \& TheHive](#external-integrations-siem--thehive)
      - [Graded Exercise / CTF Mode](#graded-exercise--ctf-mode)
    - [5. Plugins API (`/api/plugins/`)](#5-plugins-api-apiplugins)
      - [Plugin File Parity Operations](#plugin-file-parity-operations)
    - [6. Task Queue Management \& Dask Operations (`/api/tasks/` \& `/api/utils/`)](#6-task-queue-management--dask-operations-apitasks--apiutils)
      - [Unified Task Management Endpoints (`/api/tasks/`)](#unified-task-management-endpoints-apitasks)
      - [Legacy Task \& Utility Endpoints (`/api/utils/`)](#legacy-task--utility-endpoints-apiutils)
      - [Task Filters \& Query Parameters (`GET /api/tasks/`)](#task-filters--query-parameters-get-apitasks)
      - [Task Cancellation \& Retry Behavior](#task-cancellation--retry-behavior)
    - [7. Bookmarks API (`/api/bookmarks/`)](#7-bookmarks-api-apibookmarks)
    - [8. YARA Rules API (`/api/rules/` \& `/api/customrules/`)](#8-yara-rules-api-apirules--apicustomrules)
    - [9. Symbols API (`/api/symbols/`)](#9-symbols-api-apisymbols)
    - [10. Auto-Triage Playbooks API (`/api/playbooks/`)](#10-auto-triage-playbooks-api-apiplaybooks)
    - [11. Users \& Roles API (`/api/users/`)](#11-users--roles-api-apiusers)
    - [12. Global Search API (`/api/search/`)](#12-global-search-api-apisearch)
    - [13. Admin API (`/api/admin/`)](#13-admin-api-apiadmin)
  - [Python Integration Example](#python-integration-example)
    - [Option A: Personal API Token (Recommended for Automation)](#option-a-personal-api-token-recommended-for-automation)
    - [Option B: Django Session + CSRF Authentication](#option-b-django-session--csrf-authentication)
  - [Jupyter Demo Notebooks](#jupyter-demo-notebooks)

---

## Overview

Orochi provides a high-performance REST API powered by **[Django-Ninja](https://django-ninja.dev/)** and **Pydantic v2**, offering automatic request validation, type-safe serialization, and OpenAPI 3.0 schemas.

All API routes are accessible under the `/api/` prefix.

---

## Authentication

Orochi features a **Dual-Authentication API Gateway** supporting both web browser sessions and personal programmatic API bearer tokens.

### Session Authentication

Used primarily by web frontend and HTMX interactions:
1. Log in via the Orochi web interface at `https://localhost` (or authenticate via `POST /accounts/login/`).
2. Pass the standard session cookie (`sessionid`) and CSRF token (`csrftoken` with header `X-CSRFToken`) in automated HTTP requests.

### Personal API Tokens (Bearer)

For automated scripts, CLI tools, SOAR playbooks, and external integrations:
1. Generate an API token via the UI or `POST /api/auth/tokens/`.
2. Include the token in the standard `Authorization` header:
   ```http
   Authorization: Bearer oro_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```
Tokens start with the `oro_` prefix. In the database, only an 8-character lookup prefix and a cryptographic SHA-256 hash are retained, guaranteeing zero-trust key storage.

---

### Error Status Codes

| Status | Meaning |
| ------ | ------- |
| `401`  | No valid session or Bearer token. |
| `403`  | Authenticated, but the role or object permission does not allow the action (e.g. a ReadOnly upload, a Reviewer deleting a dump, a non-superuser on `/api/admin/*`, reading a dump that is not shared with you). |
| `404`  | The object does not exist, or is not in the state the action needs (e.g. restoring a dump that is not in the recycle bin); delete, restore and purge also answer 404 for a dump you cannot see. |
| `400`  | The request is valid but the operation failed (validation, upstream service error); `errors` holds the reason. |

## Interactive API Documentation (Swagger & ReDoc)

Orochi automatically generates interactive OpenAPI documentation:

- **Swagger UI**: [https://localhost/api/docs](https://localhost/api/docs)
- **OpenAPI Schema (JSON)**: [https://localhost/api/openapi.json](https://localhost/api/openapi.json)

![api-swagger](images/043_api_swagger.png)

---

## API Endpoints Reference

### 0. Authentication & Tokens API (`/api/auth/`)

Authenticate sessions, manage passwords, and issue personal programmatic Bearer API tokens for headless CLI, scripts, and automation pipelines.

| Method   | Endpoint                           | Description                                     | Permissions  |
| -------- | ---------------------------------- | ----------------------------------------------- | ------------ |
| `POST`   | `/api/auth/`                       | Authenticate with username/password (session)   | Public       |
| `DELETE` | `/api/auth/`                       | Log out current session (`204 No Content`)      | Session Auth |
| `GET`    | `/api/auth/tokens/`                | List all active API tokens for current user     | Session Auth |
| `POST`   | `/api/auth/tokens/`                | Create a new personal API token (`201 Created`) | Session Auth |
| `DELETE` | `/api/auth/tokens/{token_id}/`     | Revoke and permanently delete an API token      | Token Owner  |
| `POST`   | `/api/auth/request_password_reset` | Trigger password reset email (`204 No Content`) | Public       |
| `POST`   | `/api/auth/reset_password`         | Complete password reset using email token       | Public       |
| `POST`   | `/api/auth/change_password`        | Change current user's password                  | Session Auth |

> 🔒 **Note:** Token management endpoints (`/api/auth/tokens/`) intentionally require Django session authentication (`django_auth`) rather than an existing Bearer token so a leaked token cannot mint new tokens.

#### Create Personal API Token
```http
POST /api/auth/tokens/ HTTP/1.1
Content-Type: application/json

{
  "name": "SOAR Ingestion Pipeline"
}
```

**Response (201 Created):**
```json
{
  "id": 1,
  "name": "SOAR Ingestion Pipeline",
  "token_prefix": "oro_9a8b",
  "created_at": "2026-10-28T08:00:00Z",
  "last_used_at": null,
  "is_active": true,
  "token": "oro_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
}
```
> ⚠️ **Security Notice:** The plaintext `token` string is returned **only once** upon creation. Save it securely. Subsequent requests will only display `token_prefix`.

---

### 1. Folders API (`/api/folders/`)

Organize memory dumps into logical folder hierarchies.

| Method   | Endpoint              | Description                         | Permissions   |
| -------- | --------------------- | ----------------------------------- | ------------- |
| `GET`    | `/api/folders/`       | List all folders accessible to user | Authenticated |
| `POST`   | `/api/folders/`       | Create a new folder                 | Non-ReadOnly  |
| `DELETE` | `/api/folders/{name}` | Delete an existing folder by name   | Folder Owner  |

**Example: Create a Folder**
```http
POST /api/folders/ HTTP/1.1
Content-Type: application/json

{
  "name": "incident-alpha-2026"
}
```

---

### 2. Hosts API (`/api/hosts/`)

Manage host machines linked to memory dumps for temporal forensics and comparison.

| Method   | Endpoint            | Description                               | Permissions   |
| -------- | ------------------- | ----------------------------------------- | ------------- |
| `GET`    | `/api/hosts/`       | List all hosts in the system              | Authenticated |
| `POST`   | `/api/hosts/`       | Create a new host or return existing host | Non-ReadOnly  |
| `DELETE` | `/api/hosts/{name}` | Delete an existing host by name           | Non-ReadOnly  |

**Example: Create a Host**
```http
POST /api/hosts/ HTTP/1.1
Content-Type: application/json

{
  "name": "workstation-corp-01"
}
```

---

### 3. Dumps API (`/api/dumps/`)

Upload, inspect, update, and delete memory captures, as well as triage findings and row annotations.

| Method   | Endpoint                                        | Description                                     | Permissions    |
| -------- | ----------------------------------------------- | ----------------------------------------------- | -------------- |
| `GET`    | `/api/dumps/`                                   | List all memory dumps with filter parameters    | Authenticated  |
| `POST`   | `/api/dumps/`                                   | Register / upload a new memory dump             | Non-ReadOnly   |
| `GET`    | `/api/dumps/{index}`                            | Get dump metadata, hashes, `status`/`status_display` (processing state) and `symbol_status` | Dump Viewer    |
| `PATCH`  | `/api/dumps/{index}`                            | Update dump metadata (name, comment, color, status, operating_system) | Dump Owner     |
| `DELETE` | `/api/dumps/{index}`                            | Move the dump to the recycle bin (`?permanent=true`, or `DUMP_RETENTION_DAYS=0`, deletes it at once with its files) | Analyst / Admin who can see it |
| `GET`    | `/api/dumps/recycle_bin`                        | Dumps in the recycle bin: who deleted them, when, and `purge_at` | Authenticated  |
| `POST`   | `/api/dumps/{index}/restore`                    | Take a dump out of the recycle bin with its previous status | Analyst / Admin who can see it |
| `DELETE` | `/api/dumps/{index}/purge`                      | Delete a recycled dump for good with its files and results | Analyst / Admin who can see it |
| `GET`    | `/api/dumps/{pks}/plugins`                      | List plugins, permissions, result state (`result`, `result_display`) and stored `row_count` | Dump Viewer    |
| `GET`    | `/api/dumps/{index}/plugin/{plugin_name}/runs`  | Runs of the plugin on the dump: user, times, versions, symbols, parameters, row hash, archived rows | Dump Viewer    |
| `GET`/`DELETE` | `/api/dumps/{index}/plugin/{plugin_name}/runs/{n}/snapshot` | Download / delete the archived rows of a run | Dump Viewer / Non-ReadOnly |
| `GET`    | `/api/dumps/{index}/integrity`                  | Integrity checks of the dump (as received, image, verifications) | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/verify`                     | Re-hash the dump in the background and record the check | Non-ReadOnly   |
| `GET`    | `/api/dumps/{pks}/plugin/{plugin_name}`         | Result state, description, `row_count` and `updated_at` per dump (rows are readable once the state is Success) | Dump Viewer    |
| `POST`   | `/api/dumps/{pks}/plugin/{plugin_name}/execute` | Execute/resubmit plugin with parameters & files | Non-ReadOnly   |
| `GET`    | `/api/dumps/{pk}/reload_symbols`                | Reload symbols for a dump                       | Dump Viewer    |
| `GET`    | `/api/dumps/{pk}/symbols/diagnosis`             | Diagnose missing/matched symbols for dump       | Dump Viewer    |
| `POST`   | `/api/dumps/{pk}/symbols/auto-resolve`          | Auto-resolve missing ISF symbols for dump       | Dump Viewer    |
| `POST`   | `/api/dumps/{pk}/symbols/retry`                 | Re-run the plugins that ended Unsatisfied/Disabled for missing symbols | Non-ReadOnly   |
| `GET`    | `/api/dumps/temporal_diff/{index_a}/{index_b}`  | Compute temporal delta (T1 vs T2 forensics)     | Dump Viewer    |
| `GET`    | `/api/dumps/{index}/process-tree`               | Get hierarchical process tree with telemetry    | Dump Viewer    |
| `GET`    | `/api/dumps/{index}/network`                    | Get network socket graph & GeoIP report         | Dump Viewer    |
| `GET`    | `/api/dumps/{index}/iocs`                       | List extracted IOCs with filters                | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/iocs/scan`                  | Scan dump plugin results for IOCs               | Non-ReadOnly   |
| `POST`   | `/api/dumps/{index}/iocs/{ioc_id}/enrich`       | Enrich single IOC via Threat Intel services     | Non-ReadOnly   |
| `POST`   | `/api/dumps/{index}/iocs/enrich-all`            | Batch enrich all IOCs for dump                  | Non-ReadOnly   |
| `POST`   | `/api/dumps/{index}/export-misp`                | Export selected/all IOCs to MISP                | Non-ReadOnly   |
| `GET`    | `/api/dumps/{index}/timeline`                   | Retrieve structured timeline stream & stats     | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/sandbox/submit`             | Submit extracted file to CAPE/Cuckoo sandbox    | Non-ReadOnly   |
| `GET`    | `/api/dumps/{index}/secrets`                    | Retrieve detected memory secrets and tokens     | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/secrets/scan`               | Run YARA-X memory secrets scanning on demand    | Non-ReadOnly   |
| `GET`    | `/api/dumps/{index}/triage`                     | Get forensic behavioral triage report & risk    | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/triage/evaluate`            | Re-evaluate behavioral detection rules          | Non-ReadOnly   |
| `POST`   | `/api/dumps/promote_finding`                    | Promote secret or triage finding to Case        | Non-ReadOnly   |
| `GET`    | `/api/dumps/{index}/narrative`                  | Get latest AI triage narrative & guardrails     | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/narrative/generate`         | Generate on-demand local Ollama AI narrative    | Non-ReadOnly   |
| `GET`    | `/api/dumps/values/{id}/annotations`            | List triage notes & annotations for a row       | Dump Viewer    |
| `POST`   | `/api/dumps/values/{id}/annotations`            | Add triage annotation and status to row; pass `parent_id` to reply (the list nests `replies`) | Non-ReadOnly   |
| `DELETE` | `/api/dumps/annotations/{id}`                   | Delete an existing row annotation               | Author / Admin |

#### Flexible Folder & Host Association
When creating or editing dumps via `POST /api/dumps/` or `PATCH /api/dumps/{index}`, the `folder` and `host` parameters are normalized automatically and accept any of the following formats:
- **String name**: `"incident-alpha-2026"` / `"workstation-01"` (automatically creates the folder/host if it does not yet exist)
- **Dictionary object**: `{"name": "incident-alpha-2026"}` or `{"id": 4}`
- **Integer ID**: `4`
- **Null / Empty**: `null` or `""` (removes assignment)

#### Secrets & Credentials Extraction
Extract sensitive hardcoded credentials, JWT tokens, and private keys found in memory.

**Trigger Secrets Scan:**
```http
POST /api/dumps/win10_compromised_host/secrets/scan HTTP/1.1
Content-Type: application/json
```

**Response:**
```json
[
  {
    "id": 12,
    "category": "aws",
    "category_display": "AWS Credentials",
    "rule_name": "Secret_AWS_Access_Key",
    "masked_data": "AKIA****************2E",
    "offset": "0xfa800120",
    "pid": 4096,
    "process_name": "cmd.exe",
    "created_at": "2026-09-08T14:15:00Z"
  }
]
```

#### Forensic Behavioral Triage & Risk Evaluation
Evaluate behavioral heuristic rules across structured plugin results (`pslist`, `pstree`, `psscan`, `malfind`, etc.) and compute cumulative dump health risk scores.

**Query Triage Report:**
```http
GET /api/dumps/win10_compromised_host/triage HTTP/1.1
```

**Response:**
```json
{
  "dump_index": "win10_compromised_host",
  "dump_name": "win10_compromised_host.raw",
  "risk_score": 85,
  "risk_level": "Critical",
  "total_findings": 3,
  "severity_counts": {
    "Critical": 2,
    "High": 1,
    "Medium": 0,
    "Low": 0,
    "Info": 0
  },
  "mitre_techniques": ["T1014", "T1036.005", "T1059.001"],
  "findings": [
    {
      "id": 4,
      "rule_id": "PROC_INCOHERENT_PARENT_SVCHOST",
      "rule_name": "Abnormal Parent Process for svchost.exe",
      "category": "Process Tree",
      "severity": "Critical",
      "score": 40,
      "mitre_technique": "T1036.005",
      "description": "svchost.exe was spawned by cmd.exe (PID 200) instead of services.exe.",
      "evidence_snippet": "Process: svchost.exe (PID 201) | Parent: cmd.exe (PPID 200)",
      "entity": "svchost.exe (PID 201)",
      "created_at": "2026-09-08T14:20:00Z"
    }
  ]
}
```

#### Interactive Process Tree Visualization
Retrieve the complete hierarchical process tree derived from `windows.pstree.PsTree` / `linux.pstree.PsTree` and `pslist`, enriched with command-line strings, behavioral triage detections, memory secrets, and suspicious lineage indicators.

**Query Process Tree:**
```http
GET /api/dumps/win10_compromised_host/process-tree HTTP/1.1
```

**Response:**
```json
{
  "dump_index": "win10_compromised_host",
  "dump_name": "win10_compromised_host.raw",
  "operating_system": "windows",
  "total_processes": 86,
  "suspicious_count": 3,
  "root_nodes": [
    {
      "pid": 4,
      "ppid": 0,
      "name": "System",
      "cmdline": "",
      "path": "C:\\Windows\\System32\\ntoskrnl.exe",
      "create_time": "2026-03-01 08:00:00 UTC",
      "exit_time": null,
      "threads": 142,
      "handles": 3210,
      "session_id": 0,
      "wow64": false,
      "is_suspicious": false,
      "risk_score": 0,
      "triage_findings": [],
      "secrets": [],
      "children": [
        {
          "pid": 328,
          "ppid": 4,
          "name": "smss.exe",
          "cmdline": "\\SystemRoot\\System32\\smss.exe",
          "children": []
        }
      ]
    }
  ]
}
```

#### Threat Intelligence & IOC Extraction Hub
Automated indicator extraction and multi-source threat intelligence enrichment (VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise) with 1-click MISP export and case promotion.

**1. Scan / Extract Indicators:**
```http
POST /api/dumps/{index}/iocs/scan HTTP/1.1
```

**Response:**
```json
{
  "dump_index": "win10_compromised_host",
  "dump_name": "win10_compromised_host.raw",
  "total_count": 12,
  "malicious_count": 4,
  "type_counts": {
    "ip": 3,
    "hash_sha256": 2,
    "hash_md5": 2,
    "domain": 2,
    "url": 1,
    "yara": 2
  },
  "iocs": [
    {
      "id": 101,
      "ioc_type": "ip",
      "ioc_type_display": "IP Address",
      "value": "93.184.216.34",
      "source_plugin": "windows.netscan.NetScan",
      "context": {
        "pid": 1234,
        "process": "powershell.exe"
      },
      "enrichment": {
        "abuseipdb": {
          "abuse_score": 95,
          "isp": "Evil Hosting Ltd"
        }
      },
      "is_malicious": true,
      "threat_score": 95,
      "created_at": "2026-09-11T09:00:00Z"
    }
  ]
}
```

**2. Query Extracted Indicators:**
```http
GET /api/dumps/{index}/iocs?ioc_type=ip&is_malicious=true HTTP/1.1
```

**3. Enrich Indicator via Threat Intel:**
```http
POST /api/dumps/{index}/iocs/{ioc_id}/enrich HTTP/1.1
```

**4. Batch Enrich All Indicators:**
```http
POST /api/dumps/{index}/iocs/enrich-all HTTP/1.1
```

**5. Export Indicators to MISP:**
```http
POST /api/dumps/{index}/export-misp HTTP/1.1
Content-Type: application/json

{
  "ioc_ids": [101, 102],
  "export_all_iocs": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Successfully exported 2 IOCs to MISP",
  "event_id": 789,
  "event_uuid": "3c983d95-8b82-4f33-9118-2e00e84b80b7",
  "exported_count": 2
}
```

#### Forensic Timeline Stream API
Retrieve structured chronological events, activity velocity histogram buckets, and category aggregates for Timesketch-like incident timeline navigation.

**Query Timeline Feed:**
```http
GET /api/dumps/win10_compromised_host/timeline?limit=5000 HTTP/1.1
```

**Response:**
```json
{
  "dump_index": "win10_compromised_host",
  "dump_name": "win10_compromised_host.raw",
  "stats": {
    "total_events": 1420,
    "earliest_date": "2026-03-01 08:14:02 UTC",
    "latest_date": "2026-03-01 11:32:15 UTC",
    "timespan_display": "3 hours, 18 mins",
    "categories_count": 6,
    "max_density": 84
  },
  "categories": [
    {
      "key": "process",
      "name": "Process Activity",
      "count": 612,
      "icon": "fa-solid fa-gears",
      "color": "#a855f7",
      "badge_bg": "bg-purple-100 dark:bg-purple-950/60",
      "badge_text": "text-purple-700 dark:text-purple-300",
      "border": "border-purple-300 dark:border-purple-800"
    },
    {
      "key": "network",
      "name": "Network Sockets",
      "count": 310,
      "icon": "fa-solid fa-network-wired",
      "color": "#3b82f6",
      "badge_bg": "bg-blue-100 dark:bg-blue-950/60",
      "badge_text": "text-blue-700 dark:text-blue-300",
      "border": "border-blue-300 dark:border-blue-800"
    }
  ],
  "histogram": [
    {
      "index": 0,
      "start": "08:14:02",
      "start_iso": "2026-03-01T08:14:02",
      "end_iso": "2026-03-01T08:20:38",
      "count": 24,
      "height_pct": 28,
      "category_counts": { "process": 18, "network": 6 }
    }
  ],
  "events": [
    {
      "id": 101,
      "value_id": 4022,
      "dump_name": "win10_compromised_host.raw",
      "dump_index": "win10_compromised_host",
      "dump_color": "#3b82f6",
      "timestamp_iso": "2026-03-01T08:14:02",
      "timestamp_display": "2026-03-01 08:14:02 UTC",
      "relative_delta": "+0s",
      "delta_seconds": 0.0,
      "plugin": "windows.pslist.PsList",
      "category": "process",
      "category_name": "Process Activity",
      "category_icon": "fa-solid fa-gears",
      "category_color": "#a855f7",
      "description": "svchost.exe PID 1024 PPID 620 ThreadCount 14"
    }
  ]
}
```

#### Finding Promotion
Escalate any detected memory secret or behavioral triage finding directly into an active investigation case as a formal **Finding**.

**Request:**
```http
POST /api/dumps/promote_finding HTTP/1.1
Content-Type: application/json

{
  "case_id": 14,
  "item_type": "triage",
  "item_id": 4,
  "severity": "Critical",
  "mitre_technique": "T1036.005",
  "note": "Confirmed malicious svchost masquerading spawned by cmd.exe. Escalated for incident reporting.",
  "tags": ["process-tree", "masquerading", "triage"]
}
```

#### Plugin Row Annotations
Collaboratively review and triage individual rows within Volatility plugin tables.

**Add Annotation to Row:**
```http
POST /api/dumps/values/10542/annotations HTTP/1.1
Content-Type: application/json

{
  "status": "suspicious",
  "comment": "Parent PID anomalous. Injected memory region identified at 0xfa8003c0."
}
```

**Status Choices**: `under_review`, `suspicious`, `malicious`, `benign`.

#### AI First-Pass Forensic Triage Narrative
Retrieve or generate an executive forensic narrative summarizing structured plugin evidence via local Ollama inference, complete with anti-hallucination verification telemetry and cited plugin rows.

**Get Latest Dump Narrative:**
```http
GET /api/dumps/win10_compromised_host/narrative HTTP/1.1
```

**Response:**
```json
{
  "id": 1,
  "dump_index": "win10_compromised_host",
  "model_name": "llama3.2:1b",
  "evidence_hash": "e8f47b2c9a1d3e8f85f1c...",
  "raw_narrative": "## Executive Triage Summary\n\n- Hidden process diamorphine_rootkit...",
  "formatted_narrative": "<h2>Executive Triage Summary</h2>...",
  "citations": [
    {
      "type": "triage",
      "id": 2,
      "rule_name": "Hidden Process (DKOM)",
      "severity": "Critical",
      "label": "[Critical] Hidden Process (DKOM)"
    }
  ],
  "hallucination_check": {
    "is_clean": true,
    "verified_pids": [1042],
    "unverified_pids": [],
    "verified_offsets": ["0x7ffd9b8"],
    "unverified_offsets": [],
    "total_citations": 5
  },
  "created_at": "2026-09-09T07:53:55Z"
}
```

**Generate On-Demand Narrative:**
```http
POST /api/dumps/win10_compromised_host/narrative/generate?model_name=llama3.2:1b HTTP/1.1
```

#### Sandbox Submission (CAPE / Cuckoo)
Submit a file extracted from a dump (e.g. by `windows.dumpfiles` or `windows.pslist --dump`) to the CAPE / Cuckoo sandbox configured in **Admin > Services**:

```http
POST /api/dumps/{index}/sandbox/submit?filepath={index}/windows.pslist/pid.4242.exe&machine=win10&tags=orochi HTTP/1.1
```

- `filepath` is relative to the media root (or absolute) and **must be inside the dump folder** (`<MEDIA_ROOT>/<index>/`): any other path is rejected with `400`.
- Requires visibility on the dump and a non read-only role.
- The response contains the sandbox `task_id` and the raw sandbox answer.

---

### 4. Cases API (`/api/cases/`)

Manage investigation workspaces, cross-dump evidence grouping, collaborator notes, multi-host forensic graphs, unified timelines, and multi-format reporting.

| Method   | Endpoint                           | Description                                            | Permissions   |
| -------- | ---------------------------------- | ------------------------------------------------------ | ------------- |
| `GET`    | `/api/cases/`                      | List all cases accessible to user (owned/collaborated) | Authenticated |
| `POST`   | `/api/cases/`                      | Create a new case or return existing case by name      | Non-ReadOnly  |
| `PATCH`  | `/api/cases/{case_id}`             | Update status (Open/In Progress/Closed), tags, desc    | Non-ReadOnly  |
| `DELETE` | `/api/cases/{case_id}`             | Delete case and associated findings                    | Non-ReadOnly  |
| `GET`    | `/api/cases/{case_id}/graph/`      | Retrieve cross-dump forensic nodes and edges           | Authenticated |
| `POST`   | `/api/cases/{case_id}/graph/build` | Trigger background task to reconstruct forensic graph  | Non-ReadOnly  |
| `GET`    | `/api/cases/{case_id}/timeline/`   | Retrieve unified temporal timeline across all dumps (`metadata.timeline_kind`: artefact / manual / activity) | Authenticated |
| `POST`   | `/api/cases/{case_id}/timeline/`   | Add a manual timeline event (`timestamp`, `event_type`, `description`) | Non-ReadOnly  |
| `DELETE` | `/api/cases/{case_id}/timeline/{event_id}/` | Delete a manual timeline event (activity events are kept) | Non-ReadOnly  |
| `GET`    | `/api/cases/{case_id}/bundle`      | Download the `.orochi.zip` Case Bundle (SHA-256 manifest) | Authenticated |
| `POST`   | `/api/cases/import-bundle`         | Verify and import a Case Bundle (multipart `bundle`, optional `name`) | Non-ReadOnly  |
| `POST`   | `/api/cases/{case_id}/cortex/analyze` | Run a Cortex analyzer on an evidence's extracted file (`evidence_id`, `analyzer_id`) | Non-ReadOnly  |
| `GET`    | `/api/cases/{case_id}/notes/`      | List collaborative case notes                          | Authenticated |
| `POST`   | `/api/cases/{case_id}/notes/`      | Add a new collaborative markdown note                  | Non-ReadOnly  |
| `PATCH`  | `/api/cases/{case_id}/notes/{id}`  | Update existing note content                           | Note Author   |
| `DELETE` | `/api/cases/{case_id}/notes/{id}`  | Remove note                                            | Note Author   |
| `GET`    | `/api/cases/{case_id}/export`      | Export case dossier (Markdown, HTML, PDF, STIX 2.1)    | Authenticated |

#### Cross-Dump Multi-Host Forensic Graph
Extracts and links processes, listening sockets, injected memory regions, and parent-child execution lineages across multiple dumps within the case:

**Trigger Graph Rebuild:**
```http
POST /api/cases/1/graph/build HTTP/1.1
```
**Response:**
```json
{
  "status": "queued",
  "message": "Case forensic graph rebuild task scheduled."
}
```

**Retrieve Graph Data:**
```http
GET /api/cases/1/graph/ HTTP/1.1
```
**Response:**
```json
{
  "nodes": [
    {
      "id": "node_proc_1024",
      "label": "svchost.exe (PID 1024)",
      "entity_type": "process",
      "dump_name": "host-a.raw",
      "properties": {"pid": 1024, "ppid": 620, "path": "C:\\Windows\\System32\\svchost.exe"}
    },
    {
      "id": "node_sock_445",
      "label": "0.0.0.0:445 (LISTENING)",
      "entity_type": "socket",
      "dump_name": "host-a.raw",
      "properties": {"proto": "TCP", "port": 445}
    }
  ],
  "edges": [
    {
      "source": "node_proc_1024",
      "target": "node_sock_445",
      "relation": "bound_to",
      "weight": 1.0
    }
  ]
}
```

#### Unified Case Timeline Stream
Stream all chronological events (process creations, network connections, file accesses) across every dump associated with the case:

```http
GET /api/cases/1/timeline/?limit=50&offset=0&category=process HTTP/1.1
```

#### Collaborative Case Notes
Add, update, or remove live collaborative markdown notes shared among all analysts working on the case:

```http
POST /api/cases/1/notes/ HTTP/1.1
Content-Type: application/json

{
  "content": "Observed lateral movement from Host A (10.0.0.5) to Host B (10.0.0.12) via SMB named pipe."
}
```

#### Multi-Format Case Report Export
Export the full case dossier with executive summary, metadata, evidence dumps, findings, and timeline:

```http
GET /api/cases/1/export?format=pdf HTTP/1.1
GET /api/cases/1/export?format=markdown HTTP/1.1
GET /api/cases/1/export?format=html HTTP/1.1
GET /api/cases/1/export?format=stix HTTP/1.1
```
- `pdf`: Publication-ready formatted PDF report generated via WeasyPrint.
- `markdown`: Full technical Markdown report.
- `html`: Self-contained standalone HTML report with embedded CSS.
- `stix`: OASIS STIX 2.1 JSON bundle containing custom `report`, `observed-data`, and `file` cyber observable objects.

#### Real-Time Case Presence WebSocket
Track real-time analyst presence in an active case workspace:

```
wss://localhost/ws/case/{case_id}/presence/
```
Broadcasts `analyst_joined` and `analyst_left` events to ensure analysts avoid colliding on the same forensic artifacts.

#### External Integrations: SIEM & TheHive
Both require the corresponding service in **Admin > Services** (see the [Services Guide](Services-and-MaxMind-Guide.md#siem-thehive-and-cape-sandbox)) and a non read-only role.

| Method | Endpoint                                   | Description                                                                                                                                                                                                      |
| ------ | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST` | `/api/cases/{id}/siem/forward?provider=`   | Send case findings (with severity and MITRE technique) and up to 200 IOCs to the SIEM. `provider` (`splunk`, `elastic`, `sentinel`) overrides the configured one. Returns `502` when the SIEM rejects the event. |
| `POST` | `/api/cases/{id}/export/thehive?push=true` | Create a TheHive 5 case: findings become tasks, IOCs become observables. With `push=false` only the TheHive payload is returned, nothing is sent.                                                                |

The same actions are available from the case page (**TheHive** / **SIEM** buttons, shown only when the service is configured).

#### Graded Exercise / CTF Mode
Turn a case into a training exercise: the owner defines questions with an expected answer, collaborators submit answers and get points, hints cost points.

| Method   | Endpoint                                             | Who                                                                             |
| -------- | ---------------------------------------------------- | ------------------------------------------------------------------------------- |
| `GET`    | `/api/cases/{id}/ctf/questions`                      | Case members. Hint text is `null` until unlocked (always visible to the owner). |
| `POST`   | `/api/cases/{id}/ctf/questions`                      | Case owner or superuser. Also sets the case `is_ctf` flag.                      |
| `DELETE` | `/api/cases/{id}/ctf/questions/{question_id}`        | Case owner or superuser.                                                        |
| `POST`   | `/api/cases/{id}/ctf/questions/{question_id}/submit` | Case members.                                                                   |
| `POST`   | `/api/cases/{id}/ctf/hints/{hint_id}/unlock`         | Case members.                                                                   |
| `GET`    | `/api/cases/{id}/ctf/objectives`                     | Case members (`criteria` hidden from non-managers).                             |
| `POST`   | `/api/cases/{id}/ctf/objectives`                     | Case owner or superuser. Create a ground-truth forensic discovery objective.    |
| `DELETE` | `/api/cases/{id}/ctf/objectives/{objective_id}`      | Case owner or superuser.                                                        |
| `POST`   | `/api/cases/{id}/ctf/objectives/from-evidences`      | Case owner or superuser. Promote Golden Case Evidences into objectives.         |
| `POST`   | `/api/cases/{id}/ctf/discoveries/submit`             | Case members. Evaluate a Volatility row or `evidence_id` against ground truth.  |
| `GET`    | `/api/cases/{id}/ctf/metrics`                        | Case members. Returns `tp`, `fp`, `fn`, `precision`, `recall`, `f1_score`.      |
| `PATCH`  | `/api/cases/{id}/ctf/settings`                       | Case owner or superuser (`ctf_mode`, `ctf_fp_penalty`, `ctf_first_blood_bonus`, `ctf_dynamic_scoring`, `ctf_published`). |
| `GET`    | `/api/cases/{id}/ctf/scenario/export`                | Case owner or superuser (`?format=yaml\|json`).                                 |
| `POST`   | `/api/cases/{id}/ctf/scenario/import`                | Case owner or superuser. Import YAML/JSON scenario payload.                     |
| `GET`    | `/api/cases/{id}/ctf/leaderboard`                    | Case members (empty in Competition blind mode for non-managers).                |
| `POST`   | `/api/cases/{id}/ctf/objective-hints/{hint_id}/unlock` | Case members and participants. The cost is deducted when the objective is discovered. |
| `GET`    | `/api/cases/{id}/ctf/attack-progress`                | Case members and participants (`{"blind": true}` in Competition mode for non-managers). |
| `GET`    | `/api/cases/ctf/challenges`                          | Authenticated users. Published challenges with `private_case_id` when already started. |
| `POST`   | `/api/cases/ctf/challenges/{id}/start`               | Authenticated users. Creates (or returns) the private participant case and shares the challenge dumps. |

```http
POST /api/cases/7/ctf/questions HTTP/1.1
Content-Type: application/json

{
  "question_text": "Which IP is the C2 server?",
  "answer": "203.0.113.7",
  "points": 100,
  "order": 1,
  "hints": [{"hint_text": "Look at netscan foreign addresses", "cost": 25}]
}
```

```http
POST /api/cases/7/ctf/questions/3/submit HTTP/1.1
Content-Type: application/json

{"answer": "203.0.113.7"}
```
```json
{"submission_id": 12, "is_correct": true, "already_solved": false, "awarded_points": 75}
```

```http
POST /api/cases/7/ctf/discoveries/submit HTTP/1.1
Content-Type: application/json

{
  "plugin": "windows.pstree.PsTree",
  "result_row": {"PID": 4820, "ImageFileName": "svchost.exe"},
  "submitted_mitre": "T1055.001"
}
```
```json
{
  "is_tp": true,
  "is_fp": false,
  "is_duplicate": false,
  "is_first_blood": true,
  "mitre_matched": true,
  "awarded_points": 135,
  "objective_id": 4,
  "objective_title": "Hollowed svchost.exe (PID 4820)",
  "submission_id": 19
}
```

- Answers are compared case-insensitively, ignoring surrounding spaces. Only the SHA-256 of the normalized answer is stored.
- A question is scored once per user (enforced by the database); later submissions return `already_solved: true`.
- Discovery submissions use 3-tier canonical entity matching across plugins (`pslist` ↔ `pstree`, `netscan` ↔ `netstat`, hex-normalized `malfind`, wildcard `registry`, `yara`, `file`, and regex). Duplicates score `0` without penalty; unmatched artifacts incur `-ctf_fp_penalty`.
- Live leaderboard updates are broadcast over WebSockets at `wss://<host>/ws/case/{id}/ctf/` (authenticated case members only).
- More than 10 wrong answers per minute on the same question return `429`.
- The same rules apply to the **CTF Challenge** panel of the case page. Questions, objectives, and read-only submissions can also be audited in Django Admin.

---

### 5. Plugins API (`/api/plugins/`)

Inspect, manage, upload, and configure Volatility 3 analysis plugins with role-based authorization and full custom plugin file parity. (To execute a plugin on one or more dumps, use `POST /api/dumps/{pks}/plugin/{plugin_name}/execute`.)

| Method   | Endpoint                              | Description                                  | Permissions    |
| -------- | ------------------------------------- | -------------------------------------------- | -------------- |
| `GET`    | `/api/plugins/`                       | List available Volatility plugins            | Authenticated  |
| `GET`    | `/api/plugins/{name}`                 | Get single plugin details                    | Authenticated  |
| `GET`    | `/api/plugins/{name}/parameters`      | List configurable parameters for a plugin    | Authenticated  |
| `POST`   | `/api/plugins/{name}/enable/{enable}` | Toggle auto-run preference for current user  | Authenticated  |
| `POST`   | `/api/plugins/install`                | Install new Volatility plugin from git repo  | **Admin Only** |
| `POST`   | `/api/plugins/upload`                 | Upload custom Volatility plugin ZIP archive  | **Admin Only** |
| `POST`   | `/api/plugins/sync`                   | Force plugin synchronization across workers  | **Admin Only** |
| `PUT`    | `/api/plugins/{name}`                 | Update plugin settings / `min_role`          | **Admin Only** |
| `GET`    | `/api/plugins/{name}/source`          | Inspect plugin Python source code            | Authenticated  |
| `GET`    | `/api/plugins/{name}/export`          | Export custom plugin package as ZIP archive  | Authenticated  |
| `GET`    | `/api/plugins/catalog`                | Community plugins catalog (`orochi_plugins`) with local install status | Authenticated  |
| `DELETE` | `/api/plugins/{name}`                 | Uninstall plugin & delete files from workers | **Admin Only** |

> 🔒 **Plugin Permissions**: When querying `/api/dumps/{pks}/plugins`, each returned plugin schema includes `can_execute` (boolean indicating if the current user is authorized to run it) and `min_role` (`Admin`, `Analyst`, or `Reviewer`). Attempting to execute a restricted plugin returns `403 Forbidden`. Core Volatility plugins are protected and cannot be uninstalled via `DELETE /api/plugins/{name}`.

#### Plugin File Parity Operations

- **Direct Upload (`POST /api/plugins/upload`)**:
  Upload a `.zip` archive containing custom Volatility 3 plugins (must contain at least one `.py` file) using `multipart/form-data`:
  - `file`: The `.zip` archive file.
  - `os`: Target OS (`Linux`, `Windows`, `Mac`, or `Other`).
  - `name` (optional): Display name override.
  - `author` (optional): Plugin author string.
  - `version` (optional): Plugin version string.
  - `description` (optional): Description of plugin functionality.
  - `min_role` (optional): Role requirement (`Admin`, `Analyst`, or `Reviewer`).

- **Source Inspection (`GET /api/plugins/{name}/source`)**:
  Returns the filename, source code content, and local status of any installed custom or core plugin for auditing.

- **Export Package (`GET /api/plugins/{name}/export`)**:
  Downloads an in-memory ZIP package of the custom plugin directory for offline backup, inspection, or distribution.

- **Uninstall & Purge (`DELETE /api/plugins/{name}`)**:
  Uninstalls the custom plugin, removes plugin files from local storage and all connected Dask workers, and cleans up database records.

---

### 6. Task Queue Management & Dask Operations (`/api/tasks/` & `/api/utils/`)

Monitor, inspect, filter, retry, and cancel operations across the distributed Dask cluster and manage tasks in real time.

#### Unified Task Management Endpoints (`/api/tasks/`)

| Method   | Endpoint                          | Description                                                    | Permissions    |
| -------- | --------------------------------- | -------------------------------------------------------------- | -------------- |
| `GET`    | `/api/tasks/`                     | Unified task queue query with filters, pagination, and search  | Authenticated  |
| `GET`    | `/api/tasks/summary`              | Aggregate cluster metrics, status breakdown, and worker status | Authenticated  |
| `GET`    | `/api/tasks/{task_id}`            | Detailed forensic task inspection and execution metadata       | Authenticated  |
| `POST`   | `/api/tasks/{task_id}/kill`       | Cancel / terminate a running or queued background task         | Owner or Admin |
| `POST`   | `/api/tasks/{task_id}/retry`      | Universal task retry for failed TaskLog, Result, or Dump jobs  | Non-ReadOnly   |
| `POST`   | `/api/tasks/{task_id}/prioritize` | Adjust execution priority for a queued/retrying task           | Owner or Admin |
| `POST`   | `/api/tasks/bulk/kill`            | Bulk cancellation by task IDs, dump ID, or all active tasks    | **Admin Only** |
| `DELETE` | `/api/tasks/prune`                | Prune finished TaskLog records older than N days or all        | **Admin Only** |
| `POST`   | `/api/tasks/workers/restart`      | Gracefully restart Dask worker processes to recycle resources  | **Admin Only** |

#### Legacy Task & Utility Endpoints (`/api/utils/`)

Maintained for backward compatibility and utility lookups:

| Method | Endpoint                           | Description                                                     | Permissions        |
| ------ | ---------------------------------- | --------------------------------------------------------------- | ------------------ |
| `GET`  | `/api/utils/changelog`             | Return parsed CHANGELOG entries                                 | Authenticated      |
| `GET`  | `/api/utils/dask_status`           | Returns worker nodes status and live feed of running tasks      | Authenticated      |
| `GET`  | `/api/utils/tasks/info/{task_id}`  | Detailed forensic metrics (duration, worker, parameters, error) | Authenticated      |
| `POST` | `/api/utils/tasks/kill/{task_id}`  | Cancel / terminate a running background task                    | Owner or Admin     |
| `POST` | `/api/utils/tasks/rerun/{task_id}` | Rerun a task directly                                           | **Superuser Only** |
| `GET`  | `/api/utils/maxmind?ip={ip}`       | Query MaxMind GeoLite2 ASN/City/Country data for an IP          | Authenticated      |
| `GET`  | `/api/utils/vt?path={path}`        | Retrieve cached VirusTotal report for an extracted dump file    | Authenticated      |

#### Task Filters & Query Parameters (`GET /api/tasks/`)

- `status`: Filter by state (`running`, `queued`, `completed`, `failed`, `cancelled`).
- `task_type`: Filter by category (`run_plugin`, `manage_upload`, `unzip`, `task_log`).
- `dump_id`: Restrict to tasks associated with a specific memory dump.
- `search`: Full-text search across task name, dump name, and error messages.
- `limit` / `offset`: Pagination controls (default: 50 items).

#### Task Cancellation & Retry Behavior

- **Cancellation (`POST /api/tasks/{task_id}/kill` or `POST /api/tasks/bulk/kill`)**:
  1. Identifies active Dask task keys across workers and issues `client.cancel(keys, force=True)`.
  2. Transitions dump or result status to Error with comment `Cancelled by user`.
  3. Updates associated `TaskLog` entries to `Cancelled`.
  4. Immediately frees worker concurrency slots.
- **Universal Retry (`POST /api/tasks/{task_id}/retry`)**:
  Accepts a failed `TaskLog` ID, `Result` ID (`result-<id>`), or `Dump` ID (`dump-<id>`), resets the failure state, and safely re-enqueues the execution onto Dask workers.
- **Worker Recycling (`POST /api/tasks/workers/restart`)**:
  Gracefully restarts worker child processes to clear memory fragmentation after large memory dump extractions.

---

### 7. Bookmarks API (`/api/bookmarks/`)

Manage saved queries and starred investigations.

| Method   | Endpoint                          | Description                               |
| -------- | --------------------------------- | ----------------------------------------- |
| `GET`    | `/api/bookmarks/`                 | List bookmarks with star status and query |
| `POST`   | `/api/bookmarks/`                 | Create a new bookmark                     |
| `GET`    | `/api/bookmarks/{id}`             | Get single bookmark details               |
| `PATCH`  | `/api/bookmarks/{id}`             | Update bookmark name, icon, or query      |
| `DELETE` | `/api/bookmarks/{id}`             | Delete a bookmark                         |
| `POST`   | `/api/bookmarks/{id}/star/{star}` | Toggle star status (`true` / `false`)     |

---

### 8. YARA Rules API (`/api/rules/` & `/api/customrules/`)

Manage and compile YARA rulesets for memory artifact scanning. Automated Feed Updater & Worker Synchronization (Issue #1552 / #272).

| Method   | Endpoint                                   | Description                                                        | Permissions    |
| -------- | ------------------------------------------ | ------------------------------------------------------------------ | -------------- |
| `GET`    | `/api/rules/`                              | List system & user YARA rules (DataTables paginated)               | Authenticated  |
| `POST`   | `/api/rules/`                              | Upload `.yar`/`.yara` rule files (`multipart/form-data`)           | Non-ReadOnly   |
| `PATCH`  | `/api/rules/{id}`                          | Update rule metadata / enabled state                               | Owner / Admin  |
| `GET`    | `/api/rules/{id}/download`                 | Download raw YARA rule file                                        | Authenticated  |
| `DELETE` | `/api/rules/`                              | Delete selected YARA rules                                         | Owner / Admin  |
| `POST`   | `/api/rules/build`                         | Compile selected rules into a user custom ruleset                  | Non-ReadOnly   |
| `GET`    | `/api/rules/feeds/`                        | List public YARA rule feeds with sync status, count, auto_update   | Authenticated  |
| `POST`   | `/api/rules/feeds/sync`                    | Enqueue background update of feeds and compile default rule        | **Admin Only** |
| `POST`   | `/api/rules/feeds/{id}/toggle_auto_update` | Enable or disable periodic auto-updating for a specific feed       | **Admin Only** |
| `POST`   | `/api/rules/compile_default`               | Recompile all enabled rules into default and distribute to workers | **Admin Only** |
| `POST`   | `/api/rules/sync_workers`                  | Verify and synchronize compiled YARA rules on all Dask workers     | **Admin Only** |
| `POST`   | `/api/rules/test`                          | Live YARA-X tester: run a rule against text, a dump's extracted files or indexed rows (`target_mode`) | Authenticated  |
| `POST`   | `/api/rules/scan_file`                     | Scan an uploaded `sample` with `rule_source`, `custom_rule_id` or the default ruleset (`multipart/form-data`) | Authenticated  |
| `POST`   | `/api/rules/generate`                      | Generate a YARA rule from a `malfind` hexdump or artifact strings, optionally saved to your ruleset | Non-ReadOnly   |
| `GET`    | `/api/customrules/`                        | List user-created compiled custom rulesets                         | Authenticated  |
| `POST`   | `/api/customrules/{id}/default`            | Set compiled custom ruleset as default for Volatility YARA scans   | Owner / Admin  |
| `POST`   | `/api/customrules/publish`                 | Toggle public/private visibility on custom rulesets                | Owner / Admin  |
| `GET`    | `/api/customrules/{id}/download`           | Download compiled custom ruleset                                   | Authenticated  |
| `DELETE` | `/api/customrules/`                        | Delete selected custom rulesets                                    | Owner / Admin  |

---

### 9. Symbols API (`/api/symbols/`)

Inspect and trigger Volatility symbol table updates. Modifying symbols requires the **Admin** role. Linux/ARM ISF helper (Issue #1554 / #272).

| Method   | Endpoint                       | Description                                                        | Permissions    |
| -------- | ------------------------------ | ------------------------------------------------------------------ | -------------- |
| `GET`    | `/api/symbols/`                | List installed symbol sets (OS, banner)                            | Authenticated  |
| `POST`   | `/api/symbols/banner`          | Fetch/register symbols by kernel banner string                     | **Admin Only** |
| `POST`   | `/api/symbols/upload`          | Upload custom ISF `.json`/`.json.xz` symbol files                  | **Admin Only** |
| `POST`   | `/api/symbols/upload_packages` | Upload symbol archive packages (`.zip`)                            | **Admin Only** |
| `DELETE` | `/api/symbols/delete`          | Delete a symbol file by `path` query parameter                     | **Admin Only** |
| `POST`   | `/api/symbols/isf_download`    | Download ISF symbol tables from a remote URL                       | Authenticated  |
| `POST`   | `/api/symbols/dwarf_generate`  | Generate Volatility 3 Linux ISF symbol from ELF & System.map       | **Admin Only** |
| `POST`   | `/api/symbols/btf_generate`    | Generate Volatility 3 Linux ISF symbol from BTF (`btf2json`)       | **Admin Only** |
| `GET`    | `/api/symbols/diagnostics`     | Check health and banner resolution of Volatility symbols           | Authenticated  |
| `POST`   | `/api/symbols/sync_workers`    | Synchronize and refresh symbols cache across all Dask worker nodes | **Admin Only** |

> 💡 To trigger a full Volatility Foundation symbol sync, use `GET /api/admin/symbols/update` (Superuser only) or `python manage.py symbols_sync`.

---

### 10. Auto-Triage Playbooks API (`/api/playbooks/`)

Chained execution recipes for rapid incident response triage based on target OS and threat profile (Issue #1544). Supports both built-in and user-defined custom playbooks.

| Method   | Endpoint                                      | Description                                                   | Permissions   |
| -------- | --------------------------------------------- | ------------------------------------------------------------- | ------------- |
| `GET`    | `/api/playbooks/`                             | List available playbooks (optionally filter by `?os=Windows`) | Authenticated |
| `POST`   | `/api/playbooks/`                             | Create a new custom playbook                                  | Non-ReadOnly  |
| `GET`    | `/api/playbooks/{playbook_id}`                | Retrieve playbook details, description, and chained plugins   | Authenticated |
| `PUT`    | `/api/playbooks/{playbook_id}`                | Update an existing custom playbook                            | Owner / Admin |
| `DELETE` | `/api/playbooks/{playbook_id}`                | Delete a custom playbook                                      | Owner / Admin |
| `POST`   | `/api/playbooks/{playbook_id}/launch/{index}` | Queue chained plugin execution and trigger triage on a dump   | Non-ReadOnly  |
| `POST`   | `/api/playbooks/{playbook_id}/auto_run?auto_run=true` | Run this playbook automatically on your uploads of its OS (per user) | Non-ReadOnly  |
| `GET`    | `/api/playbooks/{playbook_id}/status/{index}` | Per-plugin state and row count of the playbook's plugins on a dump | Dump Viewer   |

Custom playbooks carry a `version` that increases at every edit.

Available Playbooks:
- `win_malware_quick`: Windows Quick Malware Triage (`PsList`, `NetScan`, `Malfind`)
- `win_ransomware_hunt`: Windows Ransomware Hunt (`PsList`, `Handles`, `FileScan`, `MutantScan`)
- `win_stealth_rootkit`: Windows Stealth Rootkit Hunt (`PsScan`, `LdrModules`, `SSDT`, `DriverScan`)
- `linux_quick_triage`: Linux Quick Triage (`PsList`, `Sockstat`, `Lsmod`)
- `linux_rootkit_hunt`: Linux Rootkit & Persistence Hunt (`Check_syscall`, `Check_modules`, `Malfind`, `Bash`)
- `mac_quick_triage`: macOS Quick Triage (`PsList`, `Netstat`, `Malfind`)

---

### 11. Users & Roles API (`/api/users/`)

Manage user accounts, query operational roles, and assign permissions.

| Method   | Endpoint                     | Description                                   | Permissions        |
| -------- | ---------------------------- | --------------------------------------------- | ------------------ |
| `GET`    | `/api/users/`                | List users with assigned `role` (paginated)   | **Admin Only**     |
| `GET`    | `/api/users/me`              | Retrieve currently authenticated user profile | Authenticated      |
| `POST`   | `/api/users/`                | Create user with specified role or read-only  | **Superuser Only** |
| `DELETE` | `/api/users/{username}`      | Delete a user account                         | **Superuser Only** |
| `POST`   | `/api/users/{username}/role` | Update a user's operational role              | **Superuser Only** |

**Example: Create User with Reviewer Role**
```http
POST /api/users/ HTTP/1.1
Content-Type: application/json

{
  "username": "auditor_dave",
  "email": "dave@corp.local",
  "first_name": "Dave",
  "last_name": "Auditor",
  "password": "SecurePassword123!",
  "role": "Reviewer"
}
```

**Example: Change User Role via Query Parameter**
```http
POST /api/users/auditor_dave/role?role=Analyst HTTP/1.1
```

Available roles: `Admin`, `Analyst`, `Reviewer`, `ReadOnly`.

---

### 12. Global Search API (`/api/search/`)

Execute PostgreSQL full-text and vector search across Cases, Dumps, and Plugin Results.

| Method | Endpoint       | Description                                                           | Permissions   |
| ------ | -------------- | --------------------------------------------------------------------- | ------------- |
| `GET`  | `/api/search/` | Query across cases, dumps, and results with `q`, `scope`, and `limit` | Authenticated |

---

### 13. Admin API (`/api/admin/`)

Trigger administrative synchronization and default YARA rule compilation jobs.

| Method | Endpoint                    | Description                                                                                              | Permissions        |
| ------ | --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------ |
| `GET`  | `/api/admin/rules/update`   | Trigger YARA rules synchronization (`rules_sync`)                                                        | **Superuser Only** |
| `GET`  | `/api/admin/rules/generate` | Generate default YARA rule (`generate_default_rule`)                                                     | **Superuser Only** |
| `GET`  | `/api/admin/plugins/update` | Trigger Volatility plugins sync (`plugins_sync`)                                                         | **Superuser Only** |
| `GET`  | `/api/admin/symbols/update` | Trigger Volatility symbols sync (`symbols_sync`)                                                         | **Superuser Only** |
| `GET`  | `/api/admin/settings`       | Runtime settings and configured services. Service keys are masked (`abcd...yz`), never returned in clear | **Superuser Only** |

---

## Official Python Client & CLI (`orochi-client`)

`clients/python/` contains the official client and the `orochi-cli` command. Install it from the repository:

```bash
uv pip install ./clients/python
```

```python
from orochi_client import OrochiClient

c = OrochiClient("https://localhost", token="oro_...", verify_ssl=False)
dump = c.upload_dump("memory.raw", name="host-01", operating_system="Windows")
c.launch_playbook("win_malware_quick", dump["index"])
c.wait_for_plugin(dump["index"], "windows.pslist.PsList")       # polls the result state
print(c.get_playbook_status("win_malware_quick", dump["index"]))
open("case.md", "wb").write(c.export_case_report(1, "markdown"))
```

The CLI exposes the same operations (`orochi-cli --help`); see [clients/python/README.md](../clients/python/README.md).

## Python Integration Example

### Option A: Personal API Token (Recommended for Automation)

```python
import requests

BASE_URL = "https://localhost"
HEADERS = {"Authorization": "Bearer oro_your_personal_token_here"}

# 1. List cases
cases = requests.get(f"{BASE_URL}/api/cases/", headers=HEADERS, verify=False).json()
print("Cases:", len(cases))

# 2. Launch an Auto-Triage Playbook on a dump
res = requests.post(
    f"{BASE_URL}/api/playbooks/win_malware_quick/launch/<dump_uuid>",
    headers=HEADERS,
    verify=False,
)
print("Playbook launch:", res.json())
```

### Option B: Django Session + CSRF Authentication

```python
import requests

BASE_URL = "https://localhost"
session = requests.Session()
session.verify = False  # If using self-signed development certificates

# 1. Log in
login_data = {"login": "admin", "password": "your_password"}
session.post(f"{BASE_URL}/accounts/login/", data=login_data)
csrf_token = session.cookies.get("csrftoken")
headers = {"X-CSRFToken": csrf_token}

# 2. Create a folder (or let dump creation do it automatically)
folder_res = session.post(
    f"{BASE_URL}/api/folders/",
    json={"name": "case-2026-001"},
    headers=headers,
)
print("Folder created:", folder_res.json())

# 3. Query cluster and live tasks status
status_res = session.get(f"{BASE_URL}/api/utils/dask_status")
status_data = status_res.json()
print(f"Workers online: {status_data.get('workers_count')}")
for task in status_data.get("tasks", []):
    print(f"Active task: {task['name']} ({task['task_type']}) on {task['worker']}")

# 4. Cancel a stuck or long-running task
if status_data.get("tasks"):
    task_id = status_data["tasks"][0]["task_id"]
    kill_res = session.post(f"{BASE_URL}/api/utils/tasks/kill/{task_id}", headers=headers)
    print("Task cancellation:", kill_res.json())
```

---

## Jupyter Demo Notebooks

For interactive step-by-step tutorials using Jupyter, see the official notebooks in `examples/`:
- 🔗 [dump.ipynb](../examples/dump.ipynb) — Memory dump upload and analysis workflow
- 🔗 [rule.ipynb](../examples/rule.ipynb) — YARA rule management
- 🔗 [custom_rule.ipynb](../examples/custom_rule.ipynb) — Custom compiled YARA rulesets

---

© 2026 LDO-CERT — Collaborative Memory Forensics Platform