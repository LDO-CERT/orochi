# Orochi Cases & CTF Mode Guide

_End-to-End Investigation Management, External IR Integrations, and Graded CTF Training Exercises_

---

## Table of Contents

- [Overview](#overview)
- [Case Management Workflow](#case-management-workflow)
  - [1. Creating, Editing & Changing Case Status](#1-creating-editing--changing-case-status)
  - [2. Collaboration & Access Control](#2-collaboration--access-control)
  - [3. Collecting Evidence & Promoting Findings](#3-collecting-evidence--promoting-findings)
  - [4. MITRE ATT&CK Coverage Matrix & Navigator Export](#4-mitre-attck-coverage-matrix--navigator-export)
  - [5. Multi-Host Graph, Timeline & Real-Time Presence](#5-multi-host-graph-timeline--real-time-presence)
- [Case Reporting & External Integrations](#case-reporting--external-integrations)
  - [Interactive Case Report Modal & AI Summaries](#interactive-case-report-modal--ai-summaries)
  - [Multi-Format Export (`.tar.gz` Bundle, PDF, Markdown, HTML, STIX 2.1)](#multi-format-export-targz-bundle-pdf-markdown-html-stix-21)
  - [TheHive 5 & SIEM Forwarding](#thehive-5--siem-forwarding)
  - [CAPE / Cuckoo Sandbox Submission](#cape--cuckoo-sandbox-submission)
- [CTF Challenge Mode (Graded Training Exercises)](#ctf-challenge-mode-graded-training-exercises)
  - [Roles & Permissions in CTF Mode](#roles--permissions-in-ctf-mode)
  - [Instructor Walkthrough (Case Owner / Superuser)](#instructor-walkthrough-case-owner--superuser)
  - [Forensic Discovery Mode (Ground Truth vs. Discovery)](#forensic-discovery-mode-ground-truth-vs-discovery)
  - [Published Challenges & Private Participant Cases](#published-challenges--private-participant-cases)
  - [Solver Walkthrough (Students & Collaborators)](#solver-walkthrough-students--collaborators)
  - [Scoring, IR Metrics, Hints & Anti-Brute-Force Rules](#scoring-ir-metrics-hints--anti-brute-force-rules)
  - [YAML / JSON Scenario Import & Export](#yaml--json-scenario-import--export)
  - [Real-Time WebSocket Leaderboard](#real-time-websocket-leaderboard)
  - [Scoreboard Page & ATT&CK Progress](#scoreboard-page--attck-progress)
  - [Managing CTF Challenges via Django Admin & REST API](#managing-ctf-challenges-via-django-admin--rest-api)

---

## Overview

Orochi's **Cases** workspace turns individual memory dump plugin results into structured, collaborative digital forensic investigations — and doubles as a **graded Capture-The-Flag (CTF) training platform** for memory forensics courses and incident-response drills.

```mermaid
flowchart LR
  Dumps["Memory Dumps & Plugins"] --> Ev["Evidence & Findings"]
  Search["Global Search / Triage / IOCs"] --> Ev
  Ev --> Case["Case Workspace (/case/<pk>)"]
  Case --> Matrix["MITRE ATT&CK Matrix"]
  Case --> Reports["PDF / HTML / MD / STIX 2.1"]
  Case --> IR["TheHive 5 / SIEM / CAPE Sandbox"]
  Case --> CTF["CTF Challenge Mode & Leaderboard"]
```

---

## Case Management Workflow

### 1. Creating, Editing & Changing Case Status

Cases are listed in the left sidebar under **Cases** and opened at `/case/<pk>`:

1. Click the **➕** button next to **Cases** (`/case_create`) to open the creation modal.
2. Enter a **Name**, optional **Folder**, **Description**, **Status** (`Open`, `In Progress`, `Closed`), **Collaborators**, and optionally enable the **CTF** flag.
3. From the case header (`/case/<pk>`), click **Edit** (`/case_edit`) to update metadata or collaborators, use the status badge dropdown (`/case_change_status/<pk>`) to transition status, or click **Delete** (`/case_delete/<pk>`) to remove the case.

![Case Detail View](images/084_case_detail.png)

### 2. Collaboration & Access Control

| Capability                                              | Case Owner / Superuser | Collaborator (`Analyst` / `Reviewer`) | Collaborator (`ReadOnly`) | Non-Member  |
| :------------------------------------------------------ | :--------------------: | :-----------------------------------: | :-----------------------: | :---------: |
| View Case, Evidence, Findings & Timeline                |           ✅            |                   ✅                   |             ✅             | ❌ (404/403) |
| Edit Case, Add/Edit/Delete Evidence & Findings          |           ✅            |                   ✅                   |          ❌ (403)          |      ❌      |
| Add/Edit Collaborative Notes                            |           ✅            |                   ✅                   |          ❌ (403)          |      ❌      |
| Export Reports (PDF / HTML / MD / STIX / MITRE)         |           ✅            |                   ✅                   |             ✅             |      ❌      |
| Forward to SIEM / Export to TheHive / Submit to Sandbox |           ✅            |                   ✅                   |     ❌ (hidden / 403)      |      ❌      |
| Create or Delete CTF Questions                          |           ✅            |                ❌ (403)                |          ❌ (403)          |      ❌      |
| Submit CTF Answers, Unlock Hints & View Leaderboard     |           ✅            |                   ✅                   |             ✅             |      ❌      |

> 🔒 **RBAC 403 Enforcement:** Authenticated users who lack permission for an action receive an explicit **HTTP 403 Forbidden** response (via `role_required` / `is_not_readonly`) rather than a login redirect.

### 3. Collecting Evidence & Promoting Findings

You can attach forensic artifacts to a case from four places across Orochi:

- **Case Detail Workspace (`/case/<pk>`)**: Click **Add Evidence** (`/evidence_create`) to link a memory dump, extracted file, or plugin result, then add one or more structured **Findings** (`/finding_create/<evidence_pk>`) with **Severity** (`Low`, `Medium`, `High`, `Critical`), Markdown **Notes**, **Tags**, and **MITRE ATT&CK** technique IDs.
- **Cross-Dump Global Search (`/global_search`)**: Click **Add to Case** (`/add_to_case_from_search`) on any search match to create evidence directly inside a target case.
- **Triage, Secrets & IOC Hubs**: Click **Add to Case** (`/promote_to_finding` or `POST /api/dumps/promote_finding`) to escalate behavioral detections, leaked credentials, or malicious IOCs into pre-populated case findings.
- **Plugin Result Row Annotations (`/value_annotations/<value_id>`)**: Annotate individual plugin rows with triage statuses (`Under Review`, `Suspicious`, `Verified Threat`, `Benign`) and escalate confirmed threats into the active case.

![Promote to Case Finding](images/079_promote_to_finding.png)

### 4. MITRE ATT&CK Coverage Matrix & Navigator Export

As findings are tagged with MITRE ATT&CK technique IDs (e.g., `T1055`, `T1059.001`, `T1036.005`), Orochi automatically populates an interactive **MITRE ATT&CK Coverage Matrix** inside the case workspace.

- Click **Export MITRE Layer** (`/case_mitre_export/<pk>`) to download a JSON layer compatible with the official [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

![MITRE ATT&CK Coverage Matrix](images/070_cases_mitre_matrix.png)

### 5. Multi-Host Graph, Timeline & Real-Time Presence

- **Cross-Dump Multi-Host Forensic Graph**: Correlates processes, listening sockets, and memory injections across all dumps linked to the case (`POST /api/cases/{id}/graph/build`, `GET /api/cases/{id}/graph/`).
- **Unified Case Timeline**: Aligns events from Windows, Linux, and macOS captures into a single chronological sequence (`GET /api/cases/{id}/timeline/`).
- **Collaborative Notes & Live Presence**: Real-time analyst presence is broadcast over WebSockets (`wss://<host>/ws/case/{case_id}/presence/`), paired with shared Markdown notes (`GET/POST /api/cases/{id}/notes/`).

---

## Case Reporting & External Integrations

### Interactive Case Report Modal & AI Summaries

Click **Generate Report** in the case header (`POST /case_report/<pk>`) to render a formatted report from any installed HTML or DOCX `ReportTemplate` (seed defaults with `python manage.py seed_report_templates`):

1. Choose a **Report Template** (HTML or DOCX).
2. Optionally toggle **Generate AI Summary with Ollama** (when the **Ollama** service is configured under **Admin -> Services**).
3. Orochi compiles the case metadata, evidence, findings, MITRE techniques, and optional local LLM executive summary (`{{ ai_summary }}` / `{{ ai_summary_html }}`) without sending data to any external cloud.

![Generate Case Report Modal](images/085_case_report_modal.png)

### Multi-Format Export (`.tar.gz` Bundle, PDF, Markdown, HTML, STIX 2.1)

In addition to the downloadable **`.tar.gz` Case Bundle** (`/case_export/<pk>`) and **MITRE ATT&CK Navigator JSON layer** (`/case_mitre_export/<pk>`), the REST API exports publication-ready dossiers:

```bash
# Publication-ready PDF (WeasyPrint)
curl -k -H "Authorization: Bearer oro_..." "https://localhost/api/cases/1/export?format=pdf" -o case_1.pdf

# Technical Markdown, standalone HTML, or OASIS STIX 2.1 bundle
curl -k -H "Authorization: Bearer oro_..." "https://localhost/api/cases/1/export?format=markdown" -o case_1.md
curl -k -H "Authorization: Bearer oro_..." "https://localhost/api/cases/1/export?format=html" -o case_1.html
curl -k -H "Authorization: Bearer oro_..." "https://localhost/api/cases/1/export?format=stix" -o case_1_stix.json
```

### TheHive 5 & SIEM Forwarding

When configured under **Admin -> Services** (see [Services and MaxMind Guide](Services-and-MaxMind-Guide.md#siem-thehive-and-cape-sandbox)), two action buttons appear in the case header for non-ReadOnly users:

- **TheHive** (`POST /api/cases/{id}/export/thehive?push=true`): Creates a TheHive 5 case where findings become tasks, MITRE techniques become tags, and dump IOCs become observables. Pass `push=false` via API to preview the payload without pushing.
- **SIEM** (`POST /api/cases/{id}/siem/forward`): Forwards case findings (with severity and MITRE tags) and up to 200 IOCs to **Splunk HEC**, **Elastic**, or **Microsoft Sentinel**.

### CAPE / Cuckoo Sandbox Submission

When a **CAPE / Cuckoo Sandbox** service is configured in **Admin -> Services**:

1. Every plugin result row with an extracted binary (e.g., `windows.dumpfiles`, `windows.pslist --dump`, `windows.malfind`) shows a **Send to sandbox** flask icon beside its download button.
2. Case evidences referencing an extracted file also display a **Sandbox** button on the case detail page.
3. Clicking the button opens the **Sandbox Submit** modal (`/sandbox_submit`) where you can optionally specify an analysis VM (`machine`) and comma-separated `tags`.
4. After submission, the modal displays the created `task_id` and a direct link to the CAPE analysis task.
5. **Security Boundary**: Orochi strictly validates that the submitted file resides inside `<MEDIA_ROOT>/<dump_index>/` — any path outside the dump folder (or submitting when no CAPE service is configured) is rejected with HTTP `400`. `ReadOnly` users do not see the button and receive `403` on the API (`POST /api/dumps/{index}/sandbox/submit`).

---

## CTF Challenge Mode (Graded Training Exercises)

**CTF Mode** (`is_ctf=True`) transforms any Orochi case into an interactive, graded memory forensics exercise with questions, point-cost hints, answer hashing, brute-force throttling, and a live leaderboard.

### Roles & Permissions in CTF Mode

- **Instructor** (`can_manage`): The **Case Owner** (`case.user`) or any **Superuser**. Can create and delete questions, sees all hint texts automatically, and monitors the live leaderboard.
- **Solver** (Student / Trainee): Any user added to the case's **Collaborators** list — including **`ReadOnly` users**, making it safe to run classroom exercises where students can inspect memory dumps and plugin outputs without modifying dumps or running heavy plugins.
- **Participant**: Any user who started a **published** challenge from `/ctf/challenges`. Participants work in a private copy of the case and never see the challenge Evidence (see [Published Challenges & Private Participant Cases](#published-challenges--private-participant-cases)).

### Instructor Walkthrough (Case Owner / Superuser)

1. **Prepare the Case**: Create a case, attach the target memory dump(s) (via folder or evidence), add your students as **Collaborators**, and tick **CTF** in the case create/edit modal (or simply add your first question, which automatically enables `is_ctf=True`).
2. **Open the CTF Challenge Panel**: Open `/case/<pk>` (the panel loads from `/case/<pk>/ctf`).
3. **Add Questions** (`/case/<pk>/ctf/questions`):
   - **Question text**: The forensic question (e.g., *"Which external IP address is the C2 server?"*).
   - **Expected answer**: Normalized by stripping leading/trailing whitespace and lowercasing, then stored strictly as a **SHA-256 hash**. Plaintext answers are never persisted and cannot be read back.
   - **Points**: Base score awarded on a correct answer (default `100`).
   - **Order**: Display sequence number (default `1`).
   - **Hints** (optional, one per line): Use `cost | hint text` (e.g., `25 | Check windows.netscan ForeignAddr`). If no cost prefix is given, the hint defaults to `10` points.
4. **Manage Questions**: The instructor view shows every hint in clear text, an **Edit** form per question (`/case/<pk>/ctf/questions/<question_id>/edit`: text, points, order, hints and an optional new answer; leaving the answer blank keeps the current one) and a **Delete** button (`/case/<pk>/ctf/questions/<question_id>/delete`).
5. **Track Progress**: Monitor the live **Leaderboard** showing rank, username, total points, solved count, and last solve timestamp.

![CTF Challenge — Instructor View (Light Mode)](images/086_ctf_instructor.png)
![CTF Challenge — Instructor View (Dark Mode)](images/087_ctf_instructor_dark.png)

### Forensic Discovery Mode (Ground Truth vs. Discovery)

In addition to Jeopardy questions, Orochi supports **Forensic Discovery Mode** (`CTFObjective` & `CTFDiscoverySubmission`), which evaluates analyst triage quality against ground-truth memory artifacts using a **3-tier canonical matching engine** (`orochi/website/ctf_matcher.py`):

1. **Tier 1 — Cross-Plugin Canonical Entity Matching**: Normalizes Volatility 3 output rows across Windows, Linux, and macOS plugins into canonical forensic entities:
   - `process` (`pslist`, `pstree`, `psscan`, `cmdline`, `dlllist`, `handles`, `bash`): `(pid, name, ppid, cmdline)` — discovering PID `4820` in `windows.pstree` matches a ground-truth objective authored from `windows.pslist`.
   - `network` (`netscan`, `netstat`, `sockstat`): `(foreign_ip, foreign_port, local_ip, local_port, proto, pid)`.
   - `injection` (`malfind`, `hollowprocesses`, `processghosting`, `ldrmodules`): `(pid, name, base_address, protection)` with automatic hex normalization (`0x7ffd0000` == `2147287040`).
   - `registry` (`printkey`, `userassist`, `hivelist`, `regipy`): `(key_path, value_name, value_data)` with `*` glob wildcard support.
   - `yara` (`yarascan`, `vadyarascan`): `(rule, pid, offset)`.
   - `file` (`filescan`, `dumpfiles`, `mftscan`, `elfs`): `(name, path, hash, pid)`.
2. **Tier 2 — Raw JSON Row Predicate Matching**: Case-insensitive fallback matching directly against raw plugin row fields.
3. **Tier 3 — Regex / Pattern Matching**: Optional `"regex"` / `"pattern"` criteria evaluated against the serialized row and extracted file name.

#### Authoring Ground Truth via Golden Case
Instructors can triage a dump normally (adding **Evidence** rows and **Findings** tagged with MITRE ATT&CK techniques) and click **Golden Case** (`POST /case/<pk>/ctf/objectives/promote`) to automatically convert those evidences into canonical `CTFObjective` ground-truth items — including their linked MITRE ATT&CK technique IDs.

![CTF Discovery Mode — Instructor View](images/093_ctf_discovery_instructor.png)

### Published Challenges & Private Participant Cases

Adding students as collaborators lets everyone work in the same case, which also shows them the instructor's Golden Case Evidence. For classroom or competition use, publish the challenge instead:

1. In **Scoring & Competition Settings**, tick **Publish challenge** and select the **Challenge dumps**. Dumps referenced by the case Evidence are always included.
2. Students open **CTF** in the top bar (`/ctf/challenges`) and click **Start challenge** (`POST /ctf/challenges/<pk>/start`).
3. Orochi creates a private case owned by the student (`ctf_template` points to the challenge), grants `can_see` on the challenge dumps and opens it. Starting again returns the same case.
4. The CTF panel of the private case shows the challenge objectives, questions and leaderboard; submissions and scores are recorded on the challenge, so the instructor sees every participant in one place. Students only see their own Evidence and cannot open the challenge case itself.

![Publishing a challenge and choosing its dumps](images/104_ctf_settings_publish.png)
![CTF Challenges page](images/102_ctf_challenges.png)

### Solver Walkthrough (Students & Collaborators)

1. Open the assigned CTF case from the left sidebar (`/case/<pk>`).
2. Inspect the attached memory dump(s), Volatility plugin tables, Process Tree, IOC Hub, and Timeline to investigate each question and discovery objective.
3. **Submit Forensic Discoveries**:
   - Click the **Submit as CTF Discovery** flag icon (`fa-flag-checkered`) directly on any Volatility plugin result row (`row_actions.html` -> `/ctf_discovery_submit`) to submit that row to your CTF case with an optional MITRE ATT&CK technique ID for bonus points.
   - Alternatively, select an existing Case Evidence item in the **Submit Forensic Discovery** box inside the CTF panel (`POST /case/<pk>/ctf/discoveries/submit`).
4. **Unlock Hints (Optional)**: Locked hints display their point cost (e.g., `-25 pts`). Clicking **Unlock hint** (`/case/<pk>/ctf/hints/<hint_id>/unlock` for questions, `/case/<pk>/ctf/objective_hints/<hint_id>/unlock` for discovery objectives) prompts for confirmation, reveals the hint text, and records the unlock so its cost will be deducted when you solve that question or discover that objective.
5. **Submit Jeopardy Answers**: Enter your answer in the question's input box and submit (`/case/<pk>/ctf/questions/<question_id>/submit`).
6. **View Your Score, IR Metrics & Live Rank**: In **Practice** mode, the CTF header displays your combined score, Precision / Recall / F1-Score, TP / FP / FN breakdown, MITRE bonuses, and First Blood count.

![CTF Challenge — Solver View](images/088_ctf_solver.png)
![CTF Discovery Mode — Solver View with IR Metrics](images/094_ctf_discovery_solver.png)
![Submit Artifact as CTF Discovery Modal](images/099_ctf_discovery_row_modal.png)

### Scoring, IR Metrics, Hints & Anti-Brute-Force Rules

All rules are enforced identically across both the Web UI and REST API (`orochi/website/ctf.py`):

- **Practice vs. Competition (Blind) Mode**: Instructors can toggle between **Practice** (instant match/FP feedback and live leaderboard) and **Competition** (blind grading: submissions are recorded silently and verdicts/standings remain hidden from solvers until switched back to Practice).
- **Information Retrieval (IR) Metrics & False Positive Penalty**:
  - **True Positive (TP)**: First match against a ground-truth objective awards `effective_base + first_blood_bonus + mitre_bonus - unlocked_hint_costs` (never below `0`).
  - **Duplicate**: Re-submitting an already-discovered entity (even via another plugin) records `is_duplicate=True` with `0` points and **no penalty**.
  - **False Positive (FP)**: Submitting a benign/unmatched artifact deducts `ctf_fp_penalty` (default `15` pts), preventing "select-all" brute forcing. Total score is clamped at `>= 0`.
  - **Precision / Recall / F1**: Computed live per solver (`Precision = TP / (TP + FP)`, `Recall = TP / (TP + FN)`, `F1 = 2 * P * R / (P + R)`).
- **MITRE ATT&CK Attribution Bonus**: Submitting a valid MITRE technique ID matching `objective.required_mitre` (including sub-technique matching, e.g., `T1055.001` satisfies `T1055`) awards `objective.mitre_bonus` points.
- **First Blood Bonus & Dynamic Scoring**: Optional per-case settings (`ctf_first_blood_bonus` percentage and `ctf_dynamic_scoring` CTFd-style decay with solve count).
- **Jeopardy Rules**: Case-insensitive SHA-256 matching, single correct solve enforced by database constraint, hint penalty subtraction, and **10 wrong answers/minute** throttling (`HTTP 429`).
- **Leaderboard Tie-Breaking**: Ranked by (1) highest combined `total_points`, (2) highest `solved_count`, (3) earliest `last_solve_at`.

### YAML / JSON Scenario Import & Export

Instructors can share or version-control entire CTF scenarios (settings, discovery objectives, and questions with hashed answers and hints):

- **Export**: Click **YAML** or **JSON** in the CTF panel (`GET /case/<pk>/ctf/scenario/export?format=yaml|json`).
- **Import**: Paste or upload a YAML/JSON scenario in **Import Scenario** (`POST /case/<pk>/ctf/scenario/import`), optionally replacing existing items.

### Real-Time WebSocket Leaderboard

Connected analysts receive live leaderboard updates over WebSockets at `wss://<host>/ws/case/<case_id>/ctf/` (`CTFLeaderboardConsumer`). Authentication and case-membership authorization are strictly enforced (`4401` for anonymous, `4403` for non-members); participants of a published challenge are members. The **Live** indicator next to the leaderboard turns green only while the WebSocket is connected and shows **Offline** otherwise.

### Scoreboard Page & ATT&CK Progress

- **Scoreboard** (`/case/<pk>/ctf/scoreboard`, also linked from the CTF panel): full standings with discovery and question points, TP / FP, Precision / Recall / F1, per-objective solve counts and a solve timeline with First Blood and MITRE markers. It refreshes live over the WebSocket and stays hidden from solvers in Competition mode.
![CTF Scoreboard with solve timeline](images/103_ctf_scoreboard.png)

- **ATT&CK Progress** (CTF panel side column, `GET /api/cases/{id}/ctf/attack-progress`): objectives with a `required_mitre` grouped by tactic. Instructors see every required technique with the number of analysts who attributed it correctly; solvers only see the techniques they attributed themselves, so unsolved objectives are not revealed.

### Managing CTF Challenges via Django Admin & REST API

- **Django Admin**: Superusers can manage questions, hints, discovery objectives, and audit read-only submissions under **WEBSITE -> CTF questions / CTF objectives / CTF submissions / CTF discovery submissions**.
- **REST API** (supports both Session auth and `Authorization: Bearer oro_...`):

| Method   | Endpoint                                             | Who               | Description                                                                                         |
| :------- | :--------------------------------------------------- | :---------------- | :-------------------------------------------------------------------------------------------------- |
| `GET`    | `/api/cases/{id}/ctf/questions`                      | Case members      | List questions, solve state, and hints (`hint_text` is `null` until unlocked unless manager).       |
| `POST`   | `/api/cases/{id}/ctf/questions`                      | Owner / Superuser | Create a question (with optional `hints`) and enable `is_ctf=True`. Returns `403` for non-managers. |
| `DELETE` | `/api/cases/{id}/ctf/questions/{question_id}`        | Owner / Superuser | Delete a question. Returns `403` for non-managers.                                                  |
| `POST`   | `/api/cases/{id}/ctf/questions/{question_id}/submit` | Case members      | Submit an answer (`{"answer": "..."}`). Returns `429` if throttled.                                 |
| `POST`   | `/api/cases/{id}/ctf/hints/{hint_id}/unlock`         | Case members      | Unlock a hint and reveal `hint_text`.                                                               |
| `GET`    | `/api/cases/{id}/ctf/objectives`                     | Case members      | List discovery objectives (`criteria` is `null` for non-managers).                                  |
| `POST`   | `/api/cases/{id}/ctf/objectives`                     | Owner / Superuser | Create a ground-truth discovery objective.                                                          |
| `DELETE` | `/api/cases/{id}/ctf/objectives/{objective_id}`      | Owner / Superuser | Delete a discovery objective.                                                                       |
| `POST`   | `/api/cases/{id}/ctf/objectives/from-evidences`      | Owner / Superuser | Golden Case: promote existing Case Evidences & linked MITRE Findings into discovery objectives.     |
| `POST`   | `/api/cases/{id}/ctf/discoveries/submit`             | Case members      | Submit a Volatility plugin row or `evidence_id` (plus optional `submitted_mitre`) for evaluation.   |
| `GET`    | `/api/cases/{id}/ctf/metrics`                        | Case members      | Retrieve the caller's IR quality metrics (`tp`, `fp`, `fn`, `precision`, `recall`, `f1_score`).     |
| `PATCH`  | `/api/cases/{id}/ctf/settings`                       | Owner / Superuser | Update `ctf_mode`, `ctf_fp_penalty`, `ctf_first_blood_bonus`, and `ctf_dynamic_scoring`.            |
| `GET`    | `/api/cases/{id}/ctf/scenario/export`                | Owner / Superuser | Export CTF scenario (`?format=yaml\|json`).                                                         |
| `POST`   | `/api/cases/{id}/ctf/scenario/import`                | Owner / Superuser | Import a YAML or JSON CTF scenario.                                                                 |
| `GET`    | `/api/cases/{id}/ctf/leaderboard`                    | Case members      | Retrieve ranked combined leaderboard (including Precision, Recall, F1, and First Blood counts).     |

See [API Guide — Graded Exercise / CTF Mode](API-Guide.md#graded-exercise--ctf-mode) for full JSON request and response examples.

---

© 2026 LDO-CERT — Collaborative Memory Forensics Platform
