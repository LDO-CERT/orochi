# Orochi API Guide

_Version 2.5.0 — 2026_  
_Comprehensive REST API and Developer Integration Reference_

---

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Interactive API Documentation (Swagger & ReDoc)](#interactive-api-documentation-swagger--redoc)
- [API Endpoints Reference](#api-endpoints-reference)
  - [1. Folders API (`/api/folders/`)](#1-folders-api-apifolders)
  - [2. Hosts API (`/api/hosts/`)](#2-hosts-api-apihosts)
  - [3. Dumps API (`/api/dumps/`)](#3-dumps-api-apidumps)
    - [Secrets & Credentials Extraction](#secrets--credentials-extraction)
    - [Forensic Behavioral Triage & Risk Evaluation](#forensic-behavioral-triage--risk-evaluation)
    - [Forensic Timeline Stream API](#forensic-timeline-stream-api)
    - [Finding Promotion](#finding-promotion)
    - [Plugin Row Annotations](#plugin-row-annotations)
  - [4. Cases API (`/api/cases/`)](#4-cases-api-apicases)
  - [5. Plugins API (`/api/plugins/`)](#5-plugins-api-apiplugins)
  - [6. Task Management & Dask Operations (`/api/utils/`)](#6-task-management--dask-operations-apiutils)
  - [7. Bookmarks API (`/api/bookmarks/`)](#7-bookmarks-api-apibookmarks)
  - [8. YARA Rules API (`/api/rules/` & `/api/customrules/`)](#8-yara-rules-api-apirules--apicustomrules)
  - [9. Symbols API (`/api/symbols/`)](#9-symbols-api-apisymbols)
  - [10. Users & Roles API (`/api/users/`)](#10-users--roles-api-apiusers)
- [Python Integration Example](#python-integration-example)
- [Jupyter Demo Notebook](#jupyter-demo-notebook)

---

## Overview

Orochi provides a high-performance REST API powered by **[Django-Ninja](https://django-ninja.dev/)** and **Pydantic v2**, offering automatic request validation, type-safe serialization, and OpenAPI 3.0 schemas.

All API routes are accessible under the `/api/` prefix.

---

## Authentication

The API uses Django session-based authentication (`django_auth`).

1. Log in via the Orochi web interface at `https://localhost` (or authenticate via `POST /users/login/`).
2. Pass the standard session cookie (`sessionid`) and CSRF token (`csrftoken` with header `X-CSRFToken`) in automated HTTP requests.

---

## Interactive API Documentation (Swagger & ReDoc)

Orochi automatically generates interactive OpenAPI documentation:

- **Swagger UI**: [https://localhost/api/docs](https://localhost/api/docs)
- **OpenAPI Schema (JSON)**: [https://localhost/api/openapi.json](https://localhost/api/openapi.json)

![api-swagger](images/043_api_swagger.png)

---

## API Endpoints Reference

### 1. Folders API (`/api/folders/`)

Organize memory dumps into logical folder hierarchies.

| Method   | Endpoint               | Description                                  | Permissions    |
| -------- | ---------------------- | -------------------------------------------- | -------------- |
| `GET`    | `/api/folders/`        | List all folders accessible to user          | Authenticated  |
| `POST`   | `/api/folders/`        | Create a new folder                          | Non-ReadOnly   |
| `DELETE` | `/api/folders/{name}`  | Delete an existing folder by name            | Folder Owner   |

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

| Method   | Endpoint               | Description                                  | Permissions    |
| -------- | ---------------------- | -------------------------------------------- | -------------- |
| `GET`    | `/api/hosts/`          | List all hosts in the system                 | Authenticated  |
| `POST`   | `/api/hosts/`          | Create a new host or return existing host    | Non-ReadOnly   |
| `DELETE` | `/api/hosts/{name}`    | Delete an existing host by name              | Non-ReadOnly   |

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

| Method   | Endpoint                                          | Description                                  | Permissions    |
| -------- | ------------------------------------------------- | -------------------------------------------- | -------------- |
| `GET`    | `/api/dumps/`                                     | List all memory dumps with filter parameters | Authenticated  |
| `POST`   | `/api/dumps/`                                     | Register / upload a new memory dump          | Non-ReadOnly   |
| `GET`    | `/api/dumps/{index}`                              | Get detailed dump metadata and hashes        | Dump Viewer    |
| `PATCH`  | `/api/dumps/{index}`                              | Update dump metadata (name, color, folder)   | Dump Owner     |
| `DELETE` | `/api/dumps/{index}`                              | Delete dump and all associated results       | Dump Owner     |
| `GET`    | `/api/dumps/temporal_diff/{index_a}/{index_b}`    | Compute temporal delta (T1 vs T2 forensics)  | Dump Viewer    |
| `GET`    | `/api/dumps/{index}/secrets`                      | Retrieve detected memory secrets and tokens  | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/secrets/scan`                 | Run YARA-X memory secrets scanning on demand | Non-ReadOnly   |
| `GET`    | `/api/dumps/{index}/triage`                       | Get forensic behavioral triage report & risk | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/triage/evaluate`              | Re-evaluate behavioral detection rules       | Non-ReadOnly   |
| `POST`   | `/api/dumps/promote_finding`                      | Promote secret or triage finding to Case     | Non-ReadOnly   |
| `GET`    | `/api/dumps/{index}/narrative`                    | Get latest AI triage narrative & guardrails  | Dump Viewer    |
| `POST`   | `/api/dumps/{index}/narrative/generate`           | Generate on-demand local Ollama AI narrative | Non-ReadOnly   |
| `GET`    | `/api/dumps/values/{id}/annotations`              | List triage notes & annotations for a row    | Dump Viewer    |
| `POST`   | `/api/dumps/values/{id}/annotations`              | Add triage annotation and status to row      | Non-ReadOnly   |
| `DELETE` | `/api/dumps/annotations/{id}`                     | Delete an existing row annotation            | Author / Admin |

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
POST /api/dumps/win10_compromised_host/narrative/generate HTTP/1.1
Content-Type: application/json

{
  "model": "llama3.2:1b"
}
```

---

### 4. Cases API (`/api/cases/`)

Manage investigation workspaces, evidence grouping, collaborator permissions, and case status.

| Method   | Endpoint                  | Description                                            | Permissions    |
| -------- | ------------------------- | ------------------------------------------------------ | -------------- |
| `GET`    | `/api/cases/`             | List all cases accessible to user (owned/collaborated) | Authenticated  |
| `POST`   | `/api/cases/`             | Create a new case or return existing case by name      | Non-ReadOnly   |
| `PATCH`  | `/api/cases/{case_id}`    | Update status (Open/In Progress/Closed), tags, desc    | Non-ReadOnly   |
| `DELETE` | `/api/cases/{case_id}`    | Delete case and associated findings                    | Non-ReadOnly   |

---

### 5. Plugins API (`/api/plugins/`)

Inspect, manage, and trigger Volatility 3 analysis plugins with role-based authorization.

| Method   | Endpoint                                           | Description                                  | Permissions    |
| -------- | -------------------------------------------------- | -------------------------------------------- | -------------- |
| `GET`    | `/api/plugins/`                                    | List available Volatility plugins            | Authenticated  |
| `POST`   | `/api/plugins/run/`                                | Run plugin on selected dumps                 | Role-Checked   |
| `POST`   | `/api/plugins/install`                             | Install new Volatility plugin from git / zip | **Admin Only** |
| `PUT`    | `/api/plugins/{name}`                              | Update plugin settings / `min_role`          | **Admin Only** |
| `GET`    | `/api/plugins/results/{dump_index}/{plugin_name}`  | Retrieve structured plugin results           | Authenticated  |

> 🔒 **Plugin Permissions**: When querying `/api/dumps/{pks}/plugins`, each returned plugin schema includes `can_execute` (boolean indicating if the current user is authorized to run it) and `min_role` (`Admin`, `Analyst`, or `Reviewer`). Attempting to execute a restricted plugin returns `403 Forbidden`.

---

### 6. Task Management & Dask Operations (`/api/utils/`)

Monitor active operations across the distributed Dask cluster and manage tasks in real time.

| Method   | Endpoint                            | Description                                                     |
| -------- | ----------------------------------- | --------------------------------------------------------------- |
| `GET`    | `/api/utils/dask_status`            | Returns worker nodes status and live feed of running tasks      |
| `GET`    | `/api/utils/tasks/info/{task_id}`   | Detailed forensic metrics (duration, worker, parameters, error) |
| `POST`   | `/api/utils/tasks/kill/{task_id}`   | Cancel / terminate a running background task                    |

#### Live Task Types
- `unzip`: Compressed archive decompression tasks.
- `manage_upload`: File ingestion, storage, and SHA-256 calculation.
- `run_plugin`: Active Volatility 3 plugin executions.
- `task_log`: Maintenance, symbols sync, and rules compilation tasks.

#### Task Cancellation Behavior
Calling `POST /api/utils/tasks/kill/{task_id}`:
1. Immediately cancels the Dask task future via `client.cancel(future, force=True)`.
2. Transitions the dump or result status to Error with comment `Cancelled by user`.
3. Frees worker concurrency slots immediately.

---

### 7. Bookmarks API (`/api/bookmarks/`)

Manage saved queries and starred investigations.

| Method   | Endpoint                  | Description                               |
| -------- | ------------------------- | ----------------------------------------- |
| `GET`    | `/api/bookmarks/`         | List bookmarks with star status and query |
| `POST`   | `/api/bookmarks/`         | Create a new bookmark                     |
| `DELETE` | `/api/bookmarks/{id}`     | Delete a bookmark                         |

---

### 8. YARA Rules API (`/api/rules/` & `/api/customrules/`)

Manage and compile YARA rulesets for memory artifact scanning.

| Method   | Endpoint                  | Description                               |
| -------- | ------------------------- | ----------------------------------------- |
| `GET`    | `/api/rules/`             | List system YARA rules                    |
| `POST`   | `/api/rules/compile/`     | Compile default ruleset for Volatility    |
| `GET`    | `/api/customrules/`       | List user-created custom rulesets         |
| `POST`   | `/api/customrules/`       | Create and build custom rule file         |

---

### 9. Symbols API (`/api/symbols/`)

Inspect and trigger Volatility symbol table updates. Modifying symbols requires the **Admin** role.

| Method   | Endpoint                  | Description                               | Permissions    |
| -------- | ------------------------- | ----------------------------------------- | -------------- |
| `GET`    | `/api/symbols/`           | List installed symbol sets (OS, banner)   | Authenticated  |
| `POST`   | `/api/symbols/sync/`      | Trigger background sync with Volatility   | **Admin Only** |
| `POST`   | `/api/symbols/upload/`    | Upload custom ISF JSON or archive package | **Admin Only** |

---

### 10. Users & Roles API (`/api/users/`)

Manage user accounts, query operational roles, and assign permissions.

| Method   | Endpoint                      | Description                                       | Permissions        |
| -------- | ----------------------------- | ------------------------------------------------- | ------------------ |
| `GET`    | `/api/users/`                 | List users with assigned `role` (paginated)       | Authenticated      |
| `POST`   | `/api/users/`                 | Create user with specified role or read-only      | **Superuser Only** |
| `POST`   | `/api/users/{username}/role`  | Update a user's operational role                  | **Superuser Only** |

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

## Python Integration Example

Below is a Python example using `requests` to interact with Orochi's API:

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

## Jupyter Demo Notebook

For an interactive step-by-step tutorial using Jupyter, see the official notebook:
🔗 [local_api.ipynb](../examples/local_api.ipynb)

---

© 2026 LDO-CERT — Collaborative Memory Forensics Platform