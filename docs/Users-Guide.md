# Orochi User Guide

_Version 2.7.0 — 2026_  
_Collaborative Memory Forensics and Threat Intelligence Platform_

---

## Table of Contents

- [Quick Start](#quick-start)
- [Concepts](#concepts)
- [UI and Theming](#ui-and-theming)
- [Login](#login)
- [Plugins](#plugins)
- [Symbols Management](#symbols-management)
- [Upload Dump & Folder Organization](#upload-dump--folder-organization)
- [Executing Plugins](#executing-plugins)
- [Activity Drawer and Task Management](#activity-drawer-and-task-management)
- [Searching and Exporting Data](#searching-and-exporting-data)
- [Cross-Dump Global Search](#cross-dump-global-search)
- [Comparing Plugin Results](#comparing-plugin-results)
- [Plugin Result Row Annotations & Triage Notes](#plugin-result-row-annotations--triage-notes)
- [Secrets & Credentials Hub](#secrets--credentials-hub)
- [Forensic Behavioral Triage & Risk Engine](#forensic-behavioral-triage--risk-engine)
- [Interactive Process-Tree Visualizer](#interactive-process-tree-visualizer)
- [Network Connection Graph & Geo-Map Visualizer](#network-connection-graph--geo-map-visualizer)
- [Auto-Triage Playbooks](#auto-triage-playbooks)
- [Threat Intelligence & IOC Extraction Hub](#threat-intelligence--ioc-extraction-hub)
- [Navigable Forensic Timeline Stream (Timesketch-like)](#navigable-forensic-timeline-stream-timesketch-like)
- [AI Forensic Triage Narrative (Local Ollama Engine)](#ai-forensic-triage-narrative-local-ollama-engine)
- [Sharing Dumps](#sharing-dumps)
- [Bookmarks](#bookmarks)
- [Personal API Tokens (Headless & Automation)](#personal-api-tokens-headless--automation)
- [Cases & Investigation Management](#cases--investigation-management)
  - [Creating and Managing Cases](#creating-and-managing-cases)
  - [Evidence & Artifact Collection](#evidence--artifact-collection)
  - [Findings & MITRE ATT&CK Mapping](#findings--mitre-attck-mapping)
  - [Cross-Dump Multi-Host Forensic Graph](#cross-dump-multi-host-forensic-graph)
  - [Collaborative Case Notes & Real-Time Presence](#collaborative-case-notes--real-time-presence)
  - [Unified Cross-Dump Incident Timeline](#unified-cross-dump-incident-timeline)
  - [Multi-Format Case Reporting & STIX 2.1 Bundles](#multi-format-case-reporting--stix-21-bundles)
  - [Sending a Case to TheHive or the SIEM](#sending-a-case-to-thehive-or-the-siem)
  - [Sending Extracted Files to the Sandbox](#sending-extracted-files-to-the-sandbox)
  - [Training Exercises (CTF Mode)](#training-exercises-ctf-mode)
- [Export to MISP](#export-to-misp)
- [Deleting Dumps](#deleting-dumps)
- [YARA](#yara)
- [HEX Viewer](#hex-viewer)
- [Interactive JSON Viewer](#interactive-json-viewer)
- [Version Information](#version-information)


---

## Quick Start

Get up and running with Orochi in minutes.

1. Prepare `.envs/.local/.django` with a unique `DJANGO_SECRET_KEY` (required):
   ```bash
   cp .envs/.local/.django.example .envs/.local/.django
   echo "DJANGO_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')" >> .envs/.local/.django
   ```
2. Start the stack:
   ```bash
   docker compose up -d
   ```
3. Access the interface at [https://localhost](https://localhost) and log in with `admin` / `admin` (or register via **Sign Up** if the administrator enabled `DJANGO_ACCOUNT_ALLOW_REGISTRATION=True` and confirm via **Mailpit** at `http://localhost:8025`).
4. Upload your first memory dump.
5. Run Volatility plugins (or launch an **Auto-Triage Playbook**) and view results.
6. (Optional) Group evidence in **Cases**, run **CTF** exercises, or export findings to **MISP / TheHive / SIEM / STIX 2.1**.

💡 **Tip:** Use a color label when uploading dumps — it helps distinguish results when comparing multiple memory images.

---

## Concepts

Orochi is an open-source, collaborative GUI built on **Django** for the **Volatility 3** memory forensics framework.  
It enables distributed, high-speed analysis of memory dumps and team-based investigation workflows.

### Architecture Overview

- **Django (WSGI)** – Handles regular web requests and REST APIs.
- **Django (ASGI)** – Manages real-time WebSocket notifications and updates.
- **Dask** – Distributes workload across multiple worker nodes for concurrent plugin execution.
- **Nginx** – Serves as the reverse proxy and HTTPS frontend.

Orochi combines these components to offer a scalable and responsive analysis environment.

---

## UI and Theming

Orochi provides a modern, responsive interface powered by Tailwind CSS. You can easily toggle between Light and Dark mode using the dropdown menu in the top navigation bar. The interface utilizes HTMX for seamless, dynamic updates without full page reloads, making navigating large memory dumps fast and efficient.

## Login

Access the Orochi GUI via Nginx. If you’re running Docker locally, open:

👉 [https://localhost](https://localhost)

1. Go to the **Sign Up** page to create a new user.
2. Confirm your email via **Mailpit** (`http://localhost:8025`).
3. Log in with your new credentials.

![sign-in](images/001_sign_in.png)
![sign-up](images/002_sign_up.png)
![mailog](images/003_mailpit_mail.png)

> 🧩 **Troubleshooting:** If you don’t receive the confirmation email, open Mailpit directly and check the inbox.

---

## Plugins

Plugins are Volatility 3 modules that Orochi executes to extract forensic artifacts such as process lists, DLLs, and network connections.

Each user can select which plugins run automatically after uploading a dump.  
If none are selected, plugins can be executed manually later.

![plugin-selection](animations/plugins.gif)

### Granular Roles and Execution Permissions
Orochi enforces role-based execution boundaries (`Admin`, `Analyst`, `Reviewer`, and `ReadOnly`):
- **Role Hierarchy**: Users assigned the **Analyst** role can execute standard analysis plugins (`PsList`, `NetScan`, `Malfind`, `Bash`, etc.). Intensive dumping plugins (such as `windows.dumpfiles.DumpFiles` and `windows.vadyarascan.VadYaraScan`) require **Admin** role or an explicit user override.
- **Permission Badges & 403 Enforcement**: In the left sidebar dump tree, plugins that your account is not authorized to execute display a locked icon (🔒). Attempting to trigger a restricted plugin or open an Admin-only page (such as Symbols upload) while signed in returns an explicit **HTTP 403 Forbidden** response rather than redirecting to login.
- **Rerun Controls**: In the plugin result view, the "Rerun" action is replaced with a locked badge if execution permissions are missing.
- **User Plugin Preferences**: You can review your assigned role, default auto-run selections, and effective permissions at any time via **Account -> Plugins** (`/users/plugins/`).

![user-plugin-permissions](images/081_user_plugin_permissions.png)

> ⚙️ **Note:** Orochi supports both built-in and custom Volatility plugins added by administrators. Administrators can also grant selective per-user execution overrides for specific plugins.

---

## Symbols Management

Orochi features a centralized Symbols management interface accessible via the **Symbols** link in the top navigation bar (`/list_symbols`).

Operating system debugging symbols and Intermediate Symbol Format (ISF) tables are essential for Volatility 3 to analyze Windows, Linux, and macOS kernels accurately.

From the Symbols Hub, you can:
- **Inspect Available Symbol Tables**: Browse active and cached symbol tables across Windows, Linux, and macOS.
- **Upload Custom Symbols**: Upload custom `.json` or `.json.xz` symbol files generated from specific kernels or builds.
- **Upload Symbol Packages**: Upload archive packages containing symbol collections directly to the Volatility symbols repository.
- **Download from ISF Servers**: Automatically fetch and unpack pre-built ISF symbol tables directly from remote repositories.

---

## Upload Dump & Folder Organization

To upload a memory dump:

1. Click the **➕** button near **DUMPS**.
2. Choose your file, set the name, and select the target operating system.
3. (Optional) Assign a **Folder** and a distinct **color label** to organize and differentiate multiple dumps.
4. Wait for the upload to complete, then click **Create Index**.

![home-page](animations/upload.gif)

### Folder Organization & Autocomplete

Orochi allows you to organize multiple memory dumps into collapsible folders in the sidebar:

- **Smart Autocomplete**: Clicking or focusing the **Folder** input presents a list of all existing folders, each showing a folder icon and the number of existing dumps inside it.
- **On-the-Fly Folder Creation**: Typing a name that does not yet exist shows an interactive **Create folder "<name>"** action in the dropdown. Clicking it immediately registers the folder in the database.
- **Pre-Creation Safety Net**: Even if you submit the form without clicking the dropdown suggestion, Orochi automatically verifies and creates the new folder before saving the dump.

### Supported Formats

- Raw (`.raw`, `.mem`) and zipped (`.zip`) dumps
- Password-protected ZIP archives
- VMware snapshots (`.vmem` + `.vmss`) in a single ZIP

Large memory dumps can also be placed manually in `/media/uploads` and selected via the **Local folder** dropdown or via the API.

![upload-dump-swagger](images/061_upload_local_dump_manage.png)

After upload, press the **ℹ️** icon near the dump name to view details such as SHA-256 hash values, file size, and storage path.

![dump-info](animations/dump_info.gif)

---

## Executing Plugins

After selecting one or more dumps, the list of available Volatility plugins is displayed.

You can:

- ✅ View results for auto-executed plugins.
- ▶️ Run a plugin manually by clicking on it.
- 🔁 Re-run a plugin with custom parameters (e.g., `--dump`, `--pid`, or `--strings`).

WebSocket notifications provide real-time updates on plugin execution status.

![plugin-main](animations/main.gif)
![plugin-pstree](animations/pstree.gif)

If a plugin encounters an error, a red error log badge appears with one-click access to the full Volatility traceback.

![plugin-error](images/020_error_log.png)

### MaxMind GeoIP & ASN Resolution
When viewing results from network forensic plugins (such as `windows.netscan.NetScan`, `windows.netstat.NetStat`, and `linux.sockstat.Sockstat`), external IP address columns (`ForeignAddr`, `Destination Addr`) display an interactive map pin button:

```html
<a class="... maxmind-info" data-ip="..."><i class="fa-solid fa-map-location"></i></a>
```

Clicking the button queries Orochi's integrated MaxMind GeoLite2 engine to display the registered Autonomous System Number (ASN), ISP organization, city, country, and geographical coordinates in a popup modal.

> 📖 **Configuration:** To configure or update GeoIP databases, see the [Services and MaxMind Configuration Guide](Services-and-MaxMind-Guide.md).

---

## Activity Drawer and Task Management

Orochi features a unified **Activity Drawer** accessible from the top navigation bar, combining real-time background task monitoring with notification history.

The top navigation bar displays a live indicator:
- **Running Task Counter**: Live count of active jobs across the cluster.
- **Queued Badge**: Indicates pending jobs awaiting worker availability.
- **Animated Spinner**: Visually highlights active forensic tasks in progress.

Clicking the **Activity** button opens a 38rem slide-out drawer with two tabs:

### 1. Worker & Dask Tasks Tab

- **Live Dask Task Feed**: Tracks all operations running on Dask workers:
  - Archive extraction (`unzip`)
  - Dump ingestion & hash computation (`manage_upload`)
  - Volatility plugin analysis (`run_plugin`)
  - Maintenance & caching tasks (`TaskLog`)
- **Task Details Inspection**: Click the info icon (`ℹ️`) on any active task to inspect execution runtime duration, assigned worker node, dump OS/index metadata, plugin parameters, and live logs in a formatted inspection modal.
- **Kill / Cancel Task**: Users can safely cancel their own running tasks (and superusers can cancel any task) by clicking the cancel icon (`🚫`). Orochi aborts the Dask future immediately and marks the database status as cancelled, releasing worker threads.
- **Connected Workers**: View worker hostnames, CPU thread capacity, memory utilization, and busy/idle states.
- **Task History & Rerun**: Review recent background operations and click **Rerun** to re-submit failed tasks directly.

### 2. History Log Tab

- A persistent real-time event feed powered by WebSockets.
- Logs dump creations, plugin finishes, error notifications, and system events.
- Unread notification badges automatically dismiss when opening the drawer.

---

## Searching and Exporting Data

Orochi provides a modernized DataTables interface wrapped in a clean, elevated card container for analyzing extracted forensic artifacts.

![result-search](animations/search.gif)

### Full-Text & Column Filtering
- **Global Search**: Instant full-text search across all extracted columns with modern focus-ring inputs and live filtering.
- **Column Footers**: Dedicated per-column filter inputs (`Filter <column>...`) in the table footer allow surgical filtering by specific attributes (e.g. PID, Process Name, IP Address).

### Multi-Format Data Export
Export filtered forensic evidence directly from the toolbar:
- **CSV**: Download clean comma-separated values for custom scripting.
- **Excel**: Export formatted spreadsheets for stakeholder reporting.
- **JSON**: Export complete JSON structures for ingestion into external threat intelligence tools.
- **XML**: Export structured XML documents.

### Unmistakable Dump Selection Recognition
When analyzing multiple memory dumps side by side, Orochi makes active selections unmistakable:
- **Color Accent Border**: Active dumps display a bold 4px left border dynamically colored with the dump's assigned color (`var(--dump-color)`).
- **Soft Tinted Row**: Selected dumps feature a subtle background tint in both light and dark modes.
- **Bold Titles & Checkmarks**: High-contrast typography and clear checkbox indicators show at a glance which memory images are included in the current analysis view.


> 🔍 **Tip:** Use this to correlate artifacts across different memory captures.

---

## Cross-Dump Global Search

In addition to filtering within individual plugin tables, Orochi provides a high-performance **Cross-Dump Global Search** powered by PostgreSQL full-text search.

The global search input is prominently located in the top navigation bar and accessible across all views.

Key capabilities:
- **Simultaneous Multi-Dump Querying**: Search across all memory dumps you have access to with a single query, matching process names, command lines, IP addresses, hashes, or arbitrary memory strings.
- **Ranked Match Results**: Results are returned grouped by dump and plugin, highlighted by relevance ranking.
- **Direct Investigation Linkage**: Each search result row includes an **Add to Case** button, allowing investigators to instantly attach relevant forensic hits as evidence directly into an active investigation case.

![global-search](images/071_global_search.png)

---

## Comparing Plugin Results & Temporal Diff

### 1. Single Plugin JSON Diff (Compare-2-Results)
When two dumps are selected, choose a common plugin to compare their results side by side.  
Colors help identify results per dump, and a JSON diff highlights differences.

![result-compare](animations/diff.gif)

### 2. Temporal Diff — Same Host T1 vs T2
For timeline and delta analysis of the same machine captured at two points in time (or any two selected captures):

- **Chronological Baseline Ordering**: Orochi automatically orders dumps into **T1** (earlier baseline capture) and **T2** (later capture), displaying the elapsed delta time (e.g. `Δ Time: +2h 15m`). You can also click **Swap T1 / T2** to invert the reference perspective.
- **Processes Delta**:
  - **`+ NEW in T2`**: Processes spawned after baseline capture T1 (highlighted in emerald green).
  - **`- Terminated`**: Processes that were running in T1 but terminated before T2 (highlighted in rose).
  - **`Persisted`**: Long-running background processes active across both captures.
- **Injected Memory Regions (Malfind)**:
  - Surfaces code injection, shellcode, and hollowed binaries discovered in T2 that were absent in T1.
  - Automatically flags PE (`MZ`) and ELF executables hidden in dynamic memory.
- **Network Connections Delta**:
  - Highlights new outbound and inbound sockets active in T2.
  - One-click MaxMind GeoIP integration for foreign IP addresses.
- **All Plugins Diff (Compare-2-Results Integration)**:
  - Lists all common plugins executed across both captures, indicating whether deltas were detected, with direct access to full side-by-side JSON diffs.

You can launch Temporal Diff directly by clicking the **Temporal Diff** button in the analysis toolbar whenever two dumps are active, or via the notification banner when checking two dumps in the workbench.

![temporal-diff](images/072_temporal_diff.png)

---

## Plugin Result Row Annotations & Triage Notes

In complex investigations, multiple analysts often inspect the same forensic output concurrently. Orochi features **Row-Level Annotations & Collaborative Triage Notes**, allowing investigators to record findings, false positive classifications, and forensic hypotheses directly on individual plugin result rows.

### Key Capabilities
- **Multi-User Threaded Notes**: Click on any row within a plugin result table to view its historical investigation thread and post timestamped comments attributed to your analyst profile.
- **Triage Status Badges**: Assign standardized triage classifications to individual rows:
  - `Under Review` (Cyan): Initial triage stage under active analysis.
  - `Suspicious` (Amber): Anomalous indicator requiring cross-dump verification.
  - `Verified Threat` (Rose): Confirmed malicious activity or attacker artifact.
  - `Benign / False Positive` (Emerald): Legitimate system behavior dismissed from active investigation.
- **Inline Table Indicators**: Rows with notes or triage statuses display high-contrast status pills directly within the results table, ensuring team members immediately see what has already been triaged.
- **Direct Case Finding Escalation**: Any annotated row can be promoted into an active investigation case as a formal **Finding** with a single click.

![row-annotations](images/076_row_annotations.png)

---

## Secrets & Credentials Hub

Hardcoded secrets, API tokens, and credentials left in process memory represent high-value lateral movement artifacts. Orochi provides an integrated **Secrets & Credentials Hub** that rapidly extracts and aggregates sensitive material across memory captures using multi-threaded YARA-X pattern analysis.

### Features
- **Curated High-Entropy Detection**: Scans memory structures for AWS access keys, Azure tokens, GCP service accounts, SSH/RSA private keys (`PEM`), JWT authentication tokens, Slack webhooks, and database connection strings (`Postgres`, `MySQL`, `MongoDB`).
- **Category Filtering & Redaction**: Filter hits seamlessly by category pills (e.g. *AWS Credentials*, *Private Key PEM*, *JWT Tokens*, *API Keys*, *Database URIs*). Sensitive credential characters are masked by default to protect live operational secrets during presentations or collaborative reviews.
- **Process & Virtual Offset Attribution**: Matched secrets are correlated with originating virtual offsets and process identifiers (e.g. PID `4096` - `cmd.exe`), bridging memory extraction with process provenance.
- **One-Click Case Promotion**: Click **Add to Case** on any detected credential to escalate it into an incident case finding with pre-populated evidence metadata.

![secrets-hub](images/077_secrets_hub.png)

---

## Forensic Behavioral Triage & Risk Engine

To accelerate triage without requiring analysts to manually review thousands of benign rows, Orochi incorporates a **Forensic Behavioral Triage & Risk Engine**. The engine evaluates declarative, structured detection rules across Volatility plugin outputs (`pslist`, `pstree`, `psscan`, `malfind`, `netscan`, `cmdline`, `privileges`).

### Behavioral Detection Capabilities
- **Process Tree Anomalies**: Flags suspicious process parentage, such as critical system processes (`svchost.exe`, `lsass.exe`, `csrss.exe`) spawned outside session 0 service hierarchies or launched from interactive shells (`cmd.exe`, `powershell.exe`).
- **Direct Kernel Object Manipulation (DKOM)**: Detects hidden rootkit processes unlinked from the active process doubly-linked list by computing cross-plugin discrepancies between physical memory tag scans (`psscan`) and scheduler tables (`pslist`).
- **Memory Code Injection (Malfind)**: Surfaces unbacked executable memory regions (`PAGE_EXECUTE_READWRITE`) containing embedded PE headers (`MZ`) or shellcode preambles.
- **Living-off-the-Land & Command Line LOLBins**: Flags encoded or hidden PowerShell execution switches (`-enc`, `-w hidden`, base64 command lines) and unauthorized privilege escalations (`SeDebugPrivilege`).

### Triage Health & Cumulative Risk Scoring
- **Dynamic Risk Gauge (0 - 100)**: Aggregates detection severities into an overarching dump health score:
  - `Clean` (0): No behavioral anomalies detected.
  - `Low` (1 - 24): Minor heuristic notices.
  - `Medium` (25 - 49): Suspicious artifacts observed.
  - `High` (50 - 74): Probable malicious execution or tampering.
  - `Critical` (75 - 100): Confirmed code injection, DKOM rootkit, or active intrusion.
- **MITRE ATT&CK Correlation**: Automatically aggregates and displays all detected ATT&CK techniques (e.g. `T1036.005`, `T1055`, `T1059.001`, `T1014`, `T1071`).

![triage-risk-dashboard](images/078_triage_risk_dashboard.png)

### One-Click Finding Promotion
Every behavioral finding and extracted secret features a **💼 Add to Case** action button. Clicking this button opens the **Promote to Case Finding** dialog, allowing investigators to:
- Select an existing active investigation case or create a new case on the fly.
- Pre-populate severity classification, MITRE ATT&CK technique IDs, and structured forensic evidence snippets.
- Tag and document the finding for immediate inclusion in the incident timeline and audit reports.

![promote-to-finding](images/079_promote_to_finding.png)

---

## Interactive Process-Tree Visualizer

Understanding process execution ancestry and lineage anomalies is fundamental to memory forensics. Orochi introduces an **Interactive Process-Tree Visualizer** accessible from the dump card menu, behavioral triage view, and the dedicated **Process Tree** analysis tab.

### Key Capabilities
- **Multi-Parent Hierarchical Graph**: Reconstructs complete parent-child hierarchies from `windows.pstree.PsTree` or `linux.pstree.PsTree` outputs and cross-checks them against `pslist` to surface unlinked or orphan processes.
- **Infection Chain Tracing**: Clicking **Trace Attack Chain** on any suspicious process instantly traces the lineage upwards to its root ancestor and highlights all descendant children with animated attack path indicators.
- **Enriched Node Telemetry**: Each process node displays PID, PPID, executable image name, command-line arguments, create timestamp, thread/handle counts, and color-coded risk flags.
- **Slide-Over Process Inspector**: Clicking any process node opens a detailed side drawer containing full command lines, binary image paths, associated behavioral triage findings, and discovered memory secrets.
- **Interactive Controls**: Features intuitive mouse drag-to-pan, wheel/pinch zoom, zoom reset, Fit-to-Screen auto-layout, search-as-you-type highlighting, and filter toggles (e.g., *Show Suspicious Only*).
- **Embedded Analysis Tab**: The process tree view is integrated directly into the dump analysis workspace alongside Volatility plugin tables, allowing seamless switching between tabular data and visual hierarchy.

---

## Network Connection Graph & Geo-Map Visualizer

Orochi includes a dedicated **Network Connection Graph & Geo-Map Visualizer** (`/dump/<index>/network`) that aggregates sockets from `windows.netscan.NetScan`, `windows.netstat.NetStat`, `linux.sockstat.Sockstat`, and `mac.netstat.Netstat`:

- **Force-Directed Topology Graph**: Visualizes local processes linked to listening ports and external IP endpoints, highlighting suspicious or external C2 connections.
- **Interactive GeoIP World Map**: Plots foreign IP endpoints on a dark-tile world map using local **MaxMind GeoLite2** databases (ASN, organization, city, country, coordinates).
- **Socket Table & Inspector Drawer**: Filter connections by protocol, state, PID, or remote IP, inspect full process context in the side drawer, and export filtered sockets to **CSV**.
- **REST API**: Programmatically accessible via `GET /api/dumps/{index}/network`.

---

## Auto-Triage Playbooks

**Auto-Triage Playbooks** (`/playbooks` and `/dump/<index>/playbooks`) let analysts launch curated, OS-specific chains of Volatility 3 plugins with a single click and automatically trigger behavioral triage scoring once the plugins finish.

### Built-In Playbooks
Orochi ships with 6 predefined incident response recipes:
- **`win_malware_quick`** (Windows): Quick Malware Triage (`PsList`, `NetScan`, `Malfind`)
- **`win_ransomware_hunt`** (Windows): Ransomware Hunt (`PsList`, `Handles`, `FileScan`, `MutantScan`)
- **`win_stealth_rootkit`** (Windows): Stealth Rootkit Hunt (`PsScan`, `LdrModules`, `SSDT`, `DriverScan`)
- **`linux_quick_triage`** (Linux): Linux Quick Triage (`PsList`, `Sockstat`, `Lsmod`)
- **`linux_rootkit_hunt`** (Linux): Linux Rootkit & Persistence Hunt (`Check_syscall`, `Check_modules`, `Malfind`, `Bash`)
- **`mac_quick_triage`** (Mac): macOS Quick Triage (`PsList`, `Netstat`, `Malfind`)

### Custom Playbooks
Non-ReadOnly users can create, edit, and delete their own custom playbooks from the **Playbooks** navigation page (`/playbooks`):
1. Click **New Custom Playbook**, set a name, target OS, icon/color, tags, and select one or more Volatility plugins.
2. Filter playbooks by OS using the filter pills (`All`, `Windows`, `Linux`, `Mac`).
3. From any dump's action menu, open **Playbooks** (`/dump/<index>/playbooks`) and click **Launch** to queue the chained plugins on Dask workers (or trigger via `POST /api/playbooks/{playbook_id}/launch/{index}`).

---

## Threat Intelligence & IOC Extraction Hub

Identifying and cataloging indicators of compromise (IOCs) across memory artifacts is essential for incident attribution and enterprise threat intelligence sharing. Orochi introduces an automated per-dump **Threat Intelligence & IOC Extraction Hub** accessible from the dump card menu, behavioral triage view, process tree, and narrative screens.

### Automated Indicator Extraction
The extraction engine continuously scans Volatility plugin outputs and extracts high-confidence indicators:
- **Public Network IPs**: Extracts foreign endpoints from `windows.netscan.NetScan`, `windows.netstat.NetStat`, and `linux.sockstat.Sockstat`. Automatically excludes RFC 1918 private subnets, loopbacks, link-local, multicast, documentation ranges (RFC 5737), and wildcards (`0.0.0.0`, `255.255.255.255`).
- **File Hashes**: Gathers SHA-256 and MD5 checksums of files extracted by `windows.dumpfiles.DumpFiles`, `windows.malfind.Malfind`, and `windows.procdump.ProcDump`.
- **YARA Matches**: Catalogs detected YARA rules and signatures from `windows.vadyarascan.VadYaraScan` and memory scans with corresponding PIDs and virtual memory offsets.
- **Web Indicators**: Extracts domains and HTTP/HTTPS URLs from command lines (`windows.cmdline.CmdLine`, `linux.bash.Bash`) and process execution parameters.

### Multi-Source Threat Intelligence Enrichment
Extracted indicators can be enriched in 1-click using configured threat intelligence services:
- **VirusTotal**: Retrieves detection ratios (`positives/total`), malicious vendor counts, scan dates, and direct analysis permalinks for file hashes, IPs, and domains.
- **AbuseIPDB**: Retrieves abuse confidence scores (0-100%), total community abuse reports, ISP, and hosting/infrastructure classifications for public IPs.
- **AlienVault OTX**: Cross-references indicators against open threat exchange pulses, extracting adversary tags, targeted sectors, and malware family attributions.
- **GreyNoise**: Evaluates internet noise and scanner activity, distinguishing opportunistic mass scans and benign cloud infrastructure (`riot: true`) from targeted malicious attacks (`malicious`).
- **Composite Threat Scoring**: Automatically calculates a composite risk score (0-100) and marks high-confidence malicious indicators (`threat_score >= 50`).

### Interactive Hub Features & Actions
- **KPI Summary Ribbon**: Displays total indicators, malicious count, average threat score, and break-downs by indicator type (IPs, Hashes, Domains, URLs, YARA rules).
- **Service Integration Badges**: Visual status pills indicating configured and active threat intelligence sources (VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, MISP).
- **Search & Filter Tabs**: Filter indicators by type or status (All, Malicious Only, Clean/Unknown), or search across indicator values and originating plugins in real time.
- **1-Click MISP Export**: Export selected indicators or all malicious indicators directly into a new or existing MISP event with IDS attributes and tags (`orochi`, `memory-forensics`, `threat-intel`).
- **1-Click Add to Case**: Escalate any indicator as an investigation finding inside the Orochi Case Management workspace.
- **Multi-Format Export**: Download the indicator feed in three standard formats:
  - **STIX 2.1 JSON Bundle**: Industry-standard CTI bundle containing identity, indicator, and relationship objects.
  - **CSV Spreadsheet**: Clean spreadsheet for tabular reporting and analysis.
  - **JSON Report**: Comprehensive structured JSON containing full context, threat scores, and enrichment payloads.

---

## Navigable Forensic Timeline Stream (Timesketch-like)

Traditional tabular outputs from Volatility's `timeliner.Timeliner` plugin can be overwhelming when inspecting thousands of disparate forensic events. Orochi introduces a **Timesketch-like Navigable Forensic Timeline Stream**, replacing the tabular-only view with a rich, interactive chronological investigation interface.

### Features
- **Visual Activity Density & Velocity Histogram**: A 30-bucket time histogram visualizes event frequency over time. Click any column bar to zoom into and isolate that specific temporal slice, or use zoom presets (`All`, `Initial 25%`, `Final 25%`, `Spikes`) to rapidly pinpoint bursts of attacker activity.
- **Incident Velocity & Stats Ribbon**: Highlights critical temporal telemetry at a glance: total event count, full incident timespan (e.g. `3 hours, 18 mins`), earliest event, latest event, and peak event velocity per bucket.
- **Categorized Event Stream**: Events are automatically classified into standardized forensic domains with dedicated color-coded badges and icons:
  - **Process Activity** (Purple - `fa-gears`): Process creation, thread scans, and termination events.
  - **Network Sockets** (Blue - `fa-network-wired`): Inbound/outbound connections and listening ports.
  - **Filesystem & MFT** (Emerald - `fa-file-lines`): File creation, modification, and access timestamps.
  - **Command Shell** (Rose - `fa-terminal`): Command prompt and bash history execution replays.
- **Forensic MACB Activity Badges**: Full parsing of SleuthKit Bodyfile v3 timestamp columns (`atime`, `mtime`, `ctime`, `crtime`) and DB values (`Modified Date`, `Accessed Date`, `Changed Date`, `Created Date`) rendered as high-visibility activity badges on every event card:
  - `M` (Amber): File / Record Modified
  - `A` (Sky Blue): File / Record Accessed
  - `C` (Purple): MFT / Metadata Changed
  - `B` (Emerald): File / Record Created / Born
- **Behavioral Anomaly & Threat Overlay**: Live cross-referencing against automated detection findings (`TriageFinding`) and extracted credentials (`DumpSecret`). Matching events display high-visibility **Threat Alert** ribbons with one-click pivots, and corresponding histogram bars show pulsing threat beacon indicators.
- **Incident-Adaptive Plotly Scatter & Swimlanes**: Dynamic zoom range buttons (`10s`, `30s`, `1m`, `2m`, `All` for short bursts ≤ 300s, up to days/weeks for long timelines) with Timesketch categorical color coding and outlier-preserving decimation prioritizing rare process, network, and registry anomalies.
- **Bi-Directional Cross-Filtering**: Brushing, zooming, or lassoing on the Plotly scatter plot dynamically filters the timeline event stream below; clicking individual points scrolls directly to the corresponding forensic event card.
- **Client-Side Forensic Export**: Instant, zero-server-load pure-JS export of current filtered events to **Filtered CSV**, **SleuthKit Bodyfile v3** (`MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`), and **Timesketch JSONL**.
- **3-Way View Mode Switcher**: Instant tab toggling between **Timeline Stream** (event cards & histogram), **Scatter & Swimlanes** (interactive Plotly view), and **Tabular Grid** (classic data table).
- **Relative Delta Badging**: Each event card calculates and displays the relative elapsed time offset from the start of the incident (e.g. `+0s`, `+15s`, `+2m 30s`, `+1h 12m`), enabling instant incident replay comprehension.
- **Real-Time Search & Dual-Order Toggle**: Instant client-side filtering by process name, PID, command line, IP, or path. Toggle between **Oldest First** (incident replay order) and **Newest First** (recent triage order) with a single click.
- **Integrated Triage & Case Escalation**: Every timeline card provides direct quick actions:
  - `💬 Annotate Row`: Add triage notes and collaborative analyst comments directly to the underlying event record.
  - `💼 Add to Case`: Escalate critical timeline events as case evidence.
  - `📋 Copy Description`: Copy clean command strings and timestamps to the system clipboard.
  - `🔍 Pivot`: Filter the timeline feed by the originating plugin or entity with one click.

![timeliner-stream](images/080_timeliner_stream.png)

---

## AI Forensic Triage Narrative (Local Ollama Engine)

Interpreting thousands of structured plugin rows across an unfamiliar memory dump often requires substantial initial orientation time. Orochi provides an **AI Forensic Triage Narrative** engine that delivers an executive, first-pass investigative summary across executed plugins while strictly preserving forensic integrity and legal chain of custody.

![ai-triage-narrative](images/082_ai_triage_narrative.png)

### Strict Forensic Principles & Safeguards
1. **100% On-Premise Inference (Zero Cloud Leakage)**:
   - All language model inference runs strictly against the local, air-gapped **Ollama** container (`http://ollama:11434`, default model `llama3.2:1b` or user-configured models).
   - Sensitive memory dump data, process names, command lines, credentials, and network IPs **never leave your private infrastructure**.
2. **Immutable Chain of Custody & Evidence Hash**:
   - The exact evidence context sent to the local model is hashed using **SHA-256** and permanently recorded in the database alongside the model version, author, and timestamp.
   - Any analyst or auditor can verify that the narrative was generated strictly from the recorded forensic evidence snapshot.
3. **Deterministic Algorithmic Anti-Hallucination Layer**:
   - LLMs can occasionally hallucinate plausible-looking numbers, process IDs, or virtual memory addresses.
   - Orochi implements a deterministic post-processing verification engine that scans the model output for all asserted PIDs and hex offsets against genuine plugin records.
   - Any fabrication is immediately quarantined and visually branded with high-visibility warning badges:  
     `⚠️ Unverified PID: 666` or `⚠️ Unverified Offset: 0x7ffd9b8`.
4. **Mandatory Forensic Row Citations**:
   - Every factual assertion, anomaly, and suspicious finding cites the exact originating plugin row or triage record (e.g. `[TriageFinding:2]`, `[DumpSecret:1]`, `[Value:142]`).
   - Citations are rendered as interactive, clickable blue badges. Clicking any badge highlights its exact provenance in the **Cited Evidence Rows** inspector drawer on the right.

### Structured Narrative Sections
The generated triage briefing is organized into standardized DFIR categories:
- **Executive Triage Summary**: High-level incident orientation, suspected malware families, and critical risk findings.
- **Process Execution & Suspicious Anomalies**: Process tree anomalies, hidden rootkit processes, command lines, and suspicious privilege escalations.
- **Network Communications & External Infrastructure**: External connections, listening sockets, and jump host communications.
- **Memory Injections & Exposed Credentials**: Injected memory segments (`PAGE_EXECUTE_READWRITE`), embedded PE executables (`MZ`), and hardcoded secrets/passwords found in process memory.
- **Recommended Investigative Actions**: Concrete, prioritized next steps referencing cited findings to guide subsequent timeline, binary dump, and disk analysis.

### Interactive Controls & Export
- **Model Selector**: Switch between installed local Ollama models (e.g. `llama3.2:1b`, `mistral`, `llama3`).
- **One-Click Regeneration**: Click **Regenerate Narrative** (`✨`) to produce an updated triage assessment as new plugins complete.
- **Markdown Export**: Click **Export Markdown** (`📥`) to download a standardized report containing evidence hashes, guardrail audit statuses, and citation lists for immediate inclusion in case documentation.

---

## Sharing Dumps

You can share dumps and their results between users.

- The uploader becomes the **owner**.
- Shared users can:
  - View dumps and plugin results
  - Run or re-run plugins
  - ❌ Cannot delete dumps

| Action      | Owner | Shared User |
| ----------- | ----- | ----------- |
| View dump   | ✅    | ✅          |
| Run plugin  | ✅    | ✅          |
| Delete dump | ✅    | ❌          |

![dump-share](images/016_users_share_dump.png)

> 🤝 **Collaboration Tip:** Shared dumps enable multi-user investigation on the same evidence set.

---

## Bookmarks

Bookmarks let you quickly return to specific filtered results.

1. While viewing a result, click the **Bookmark** icon.
2. Assign a name, choose an icon (from [MTG](https://magic.wizards.com/) sets), and optionally star it for quick access.

![bookmarks](animations/bookmarks.gif)

Starred bookmarks appear in the quick-access menu. Non-starred ones are accessible under **Bookmarks** in the admin panel.

> 💡 **Tip:** Bookmarks can reference queries across multiple dumps.

---

## Personal API Tokens (Headless & Automation)

Orochi 2.7.0 supports programmatic authentication via **Personal API Tokens** (`Authorization: Bearer oro_...`) for headless scripts, CI/CD pipelines, and DFIR orchestration platforms:

1. Navigate to your user settings or use the REST API (`POST /api/auth/tokens/`).
2. Provide a descriptive label (e.g. `DFIR-Orchestrator`).
3. Copy the generated token immediately—due to zero-trust storage, the plaintext token is displayed only once.
4. Authenticate HTTP requests:
   ```bash
   curl -k -H "Authorization: Bearer oro_your_secret_token_here" https://localhost/api/cases/
   ```

---

## Cases & Investigation Management

> 📖 **Dedicated Guide:** For a complete step-by-step walkthrough of the Case Management lifecycle, Evidence & Findings, Case Reports, CAPE Sandbox submission, SIEM/TheHive export, and **CTF Challenge Mode** (for both Instructors and Solvers), see the **[Cases & CTF Mode Guide](Cases-and-CTF-Guide.md)**.

Orochi transforms memory forensics from isolated analysis into a structured incident response workflow through its built-in **Cases** management system.

Located in the left sidebar under the **Cases** header, this suite enables DFIR analysts to group evidence, document attacker activity, map findings to MITRE ATT&CK techniques, and export executive-ready incident reports.

### Creating and Managing Cases
- **Case Workspaces**: Create an investigation case by clicking the **➕** button next to **Cases**. Assign a name, folder, description, and status (**Open**, **In Progress**, **Closed**).
- **Status Management & Quick Actions**: Change status seamlessly at any time via the interactive status badge dropdown (Open, In Progress, Closed) or click the **Close Case** / **Reopen Case** action button directly in the case header.
- **CTF Mode**: Toggle the **CTF** flag for training or capture-the-flag exercises (see [Training Exercises (CTF Mode)](#training-exercises-ctf-mode)).
- **Collaboration**: Add team members as collaborators in the case modal. Collaborators can concurrently view, edit, attach evidence, and document findings on shared cases, with visual collaborator indicators in the sidebar and header.

### Evidence & Artifact Collection
Investigators can collect and attach forensic evidence to a case from multiple sources:
- **Memory Dumps**: Associate entire memory dumps to the case context.
- **Extracted Files**: Attach dumped executables, injected DLLs, or unpacked payloads.
- **Plugin Result Rows**: Directly link suspicious process entries, network connections, or injected memory sections as individual evidence items.

### Findings & MITRE ATT&CK Mapping
For each piece of evidence, analysts can record structured **Findings**:
- **Severity Classification**: Categorize findings by risk level (**Low**, **Medium**, **High**, **Critical**).
- **Investigation Notes**: Detailed markdown notes and technical commentary explaining the forensic significance.
- **Custom Tags**: Label findings with keywords (e.g. `persistence`, `lateral-movement`, `c2`).
- **MITRE ATT&CK Techniques**: Associate findings with standard ATT&CK technique IDs (e.g. `T1059` Command and Scripting Interpreter, `T1055` Process Injection).

![case-workspace](images/069_cases_workspace.png)

### Cross-Dump Multi-Host Forensic Graph
Investigations involving enterprise intrusions span multiple endpoints. Orochi automatically reconstructs cross-dump relational graphs:
- **Entity Nodes**: Maps processes, bound listening sockets, injected memory regions, and system services across all dumps attached to the case.
- **Relational Edges**: Discovers parent-child execution lineages, socket bindings, and cross-host network interactions.
- **Interactive Inspection**: Filter nodes by host, process name, or severity, and drill down directly into the underlying plugin evidence.

### Collaborative Case Notes & Real-Time Presence
- **Live Collaborative Presence**: Active analysts working on the case are tracked in real-time via WebSockets (`/ws/case/{case_id}/presence/`), showing live presence avatars and preventing duplicate analytical effort.
- **Shared Case Notes**: Investigators can record chronological, formatted Markdown notes directly in the case workspace (`/api/cases/{case_id}/notes/`), annotating hypothesis validations, lateral movement trails, and IOC correlation.

### Unified Cross-Dump Incident Timeline
As evidence, findings, and notes are compiled, Orochi sequences all forensic artifacts into a unified **Cross-Dump Timeline** (`/api/cases/{case_id}/timeline/`). Events from heterogeneous machines (Windows, Linux, macOS) are aligned chronologically, exposing attacker dwell time and kill-chain stages.

### Multi-Format Case Reporting & STIX 2.1 Bundles
Export comprehensive case dossiers tailored for executives, incident response teams, and threat intelligence sharing:
- **Publication-Ready PDF**: Professional, branded PDF incident reports formatted with cover page, finding tables, and executive summaries generated via WeasyPrint (`GET /api/cases/{id}/export?format=pdf`).
- **Technical Markdown**: Full technical report in portable GitHub Flavored Markdown (`?format=markdown`).
- **Standalone HTML**: Self-contained HTML report with responsive styling for offline archiving (`?format=html`).
- **OASIS STIX 2.1 Threat Intel Bundle**: Full machine-readable STIX 2.1 bundle (`?format=stix`) exporting custom `report`, `observed-data`, and cyber observable objects for seamless ingestion into MISP, OpenCTI, or SIEM platforms.
- **MITRE ATT&CK Enterprise Navigator**: Export tailored MITRE ATT&CK Navigator JSON layers (`/case_mitre_export/<id>`).

![case-mitre-matrix](images/070_cases_mitre_matrix.png)

### Sending a Case to TheHive or the SIEM
When the administrator has configured the services, the case header shows two extra buttons:
- **TheHive** creates a TheHive case: findings become tasks, the IOCs of the case dumps become observables, MITRE techniques become tags.
- **SIEM** sends the findings and the IOCs to Splunk, Elastic or Sentinel.

A notification confirms the result. Read-only users cannot use them.

### Sending Extracted Files to the Sandbox
When a CAPE / Cuckoo sandbox is configured, files extracted by plugins (e.g. `windows.pslist --dump`, `windows.dumpfiles`) get a **Send to sandbox** button (flask icon) next to the download button of their row, and evidences with an extracted file show a **Sandbox** button on the case page. Pick an analysis VM and tags if needed and submit: the modal shows the created task with a link to its CAPE page. Only files extracted from the dump can be sent, and read-only users do not see the button.

### Training Exercises (CTF Mode)
A case can be used as a graded exercise on one or more memory dumps. When the case has the **CTF** flag, its page shows a **CTF Challenge** panel.

**Instructor (case owner)**
1. Create the case, link the dumps (folder or evidence), add the students as **collaborators** and tick **CTF** in **Edit**.
2. In the CTF panel open **Add question**: question text, expected answer, points, order and optional hints, one per line with the cost before a `|` (`25 | Look at netscan`; without cost a hint costs 10 points).
3. The instructor view shows every hint and a delete button per question, never an answer field. Only the hash of the answer is stored, so a forgotten answer cannot be read back: delete the question and create it again.

**Students (collaborators)**
- Each question has an answer field; correct answers turn green with the points awarded.
- Locked hints show their cost: **Unlock hint** asks for confirmation, then shows the text and subtracts its cost if the question is solved afterwards.
- The header shows the student score; the **Leaderboard** ranks everybody by points, then solved questions, then time of the last solve.

Scoring rules: answers are case-insensitive; each question scores once per student; after 10 wrong answers in a minute the student must wait. Questions can also be managed in **Admin > CTF questions** and through the [API](API-Guide.md#graded-exercise--ctf-mode). For a full Instructor & Solver walkthrough, see the [Cases & CTF Mode Guide](Cases-and-CTF-Guide.md#ctf-challenge-mode-graded-training-exercises).

![CTF Instructor View](images/086_ctf_instructor.png)
![CTF Solver View](images/088_ctf_solver.png)

---

## Export to MISP

Orochi integrates natively with **MISP** (Malware Information Sharing Platform) for converting memory forensics discoveries into actionable cyber threat intelligence.

### Export Capabilities
1. **Extracted Binary Artifacts**:
   - In any plugin results table containing dumped files (`windows.dumpfiles`, `windows.malfind`, `windows.procdump`), click the **Export to MISP** button.
   - Orochi creates an event containing a `FileObject` with the binary artifact, automatically correlating any **ClamAV** detections (`av-signature` object) and **VirusTotal** analysis reports.
2. **Indicators of Compromise (IOCs)**:
   - Inside the **IOC Extraction Hub** (`/dump/<index>/iocs`), select one or more extracted indicators (or use the *Export Malicious to MISP* shortcut).
   - Orochi creates a tagged MISP event (`orochi`, `memory-forensics`, `threat-intel`) and attaches indicators as MISP attributes (`ip-dst`, `sha256`, `md5`, `domain`, `url`, `yara`) with automatic IDS detection flags.
3. **Robust Multi-Storage Resolution (Version 2.6.0)**:
   - Resolves dumped files across arbitrary storage directory depths and volume mounts.
   - Pre-validates physical file existence on disk before event submission, displaying clear, actionable alerts if files were removed.
   - Built-in connection testing utility under **Admin -> Services** (`/service/test-connection`) verifies MISP auth keys and reports instance versions.

![dump-share](images/048_misp_export.png)

### Result in MISP

Exported files, indicators, and AV signatures appear as correlated MISP objects and attributes ready for correlation across your security operations center.

![dump-share](images/050_misp_export.png)

> 🔗 **Note:** Ensure MISP API credentials and URL are configured under **Admin -> Services** before exporting.

---

## Deleting Dumps

Deleting a dump removes it and all associated plugin results permanently.

![dump-delete](animations/delete.gif)

> ⚠️ **Warning:** This action cannot be undone.

---

## YARA

Orochi provides a dedicated interface for managing YARA rules used by Volatility plugins.

![yara-user](images/065_yara_user.png)

You can:

- View rules imported and enabled by the admin.
- Perform full-text search through PostgreSQL integration.
- Build compiled YARA files for Volatility.
- Choose whether compiled files are **private** or **public**.

![yara-user-manage](images/066_yara_user_manage.png)

### Example Workflow

1. Search for rules containing “credential”.
2. Select relevant ones.
3. Build a compiled YARA file.
4. Run the Volatility `yara` plugin using that file.

![yara-user-results](images/067_yara_user_results.png)

> 🧠 **Tip:** Only the compiled file marked _default_ is used by the Volatility YARA plugin.

---

## HEX Viewer

Orochi includes a remote HEX viewer for browsing dumps directly in the browser.

![hex-view](animations/hex.gif)

You can:

- Browse through offsets.
- Jump to a specific address.
- Search for ASCII or hexadecimal values.
- View both hex and ASCII representations.

> ⚡ **Performance Tip:** Large dumps may take several seconds to load depending on size and system resources.

## Interactive JSON Viewer

Orochi incorporates a modern, full-featured interactive JSON viewer (`vanilla-jsoneditor`) to inspect complex forensic structures, plugin configurations, and raw Volatility data.

You can:
- Switch effortlessly between **Tree Mode** (collapsible nodes with property counts), **Table Mode** (flattened tabular view), and **Code Mode** (raw formatted JSON syntax).
- Search, filter, and extract nested keys within large data structures without downloading external files.
- Automatically inherits your selected **Dark** or **Light** theme preference.

![json-viewer](images/074_json_viewer.png)

---

## Version Information

- **Application:** Orochi v2.7.0
- **Frameworks:** Django, Dask, Volatility 3
- **License:** MIT
- **Repository:** [https://github.com/LDO-CERT/orochi](https://github.com/LDO-CERT/orochi)

---

© 2026 LDO-CERT — Collaborative Memory Forensics Platform

