# Orochi Admin Guide

_Version 2.5.0 — 2026_  
_Administrative Management and Maintenance Manual_

---

## Table of Contents

- [Quick Start](#quick-start)
- [Concepts](#concepts)
- [Login](#login)
- [Account Management](#account-management)
  - [Email Addresses](#email-addresses)
  - [Users](#users)
- [Website Management](#website-management)
  - [Dumps](#dumps)
  - [Extracted Dumps](#extracted-dumps)
  - [Plugins](#plugins)
  - [Results](#results)
  - [Services](#services)
    - [VirusTotal](#virustotal)
    - [MISP](#misp)
    - [Ollama](#ollama)
    - [Webhook](#webhook)
    - [Slack](#slack)
    - [Email](#email)
    - [Proxy Configuration](#proxy-configuration)
  - [User Plugins](#user-plugins)
  - [Granular Role-Based Access Control (RBAC) &amp; Plugin Permissions](#granular-role-based-access-control-rbac--plugin-permissions)
- [Updating and Maintenance](#updating-and-maintenance)
  - [Update Plugins](#update-plugins)
  - [Update Symbols](#update-symbols)
  - [Add Custom Plugins](#add-custom-plugins)
  - [Update Vendored Libraries](#update-vendored-libraries)
  - [MaxMind GeoIP Configuration](#maxmind-geoip-configuration)
- [YARA Rules Management](#yara-rules-management)
  - [Update Rules](#update-rules)
  - [Generate Default Rule](#generate-default-rule)
  - [Manage Rules](#manage-rules)
  - [Manage Rulesets](#manage-rulesets)
  - [Curated Secrets Ruleset (`secrets.yar`)](#curated-secrets-ruleset-secretsyar)
- [Forensic Behavioral Detection & Triage Engine](#forensic-behavioral-detection--triage-engine)
  - [Detection Rule Architecture](#detection-rule-architecture)
  - [Core Forensic Detection Rules](#core-forensic-detection-rules)
  - [Cumulative Risk Scoring & Severity Thresholds](#cumulative-risk-scoring--severity-thresholds)
  - [Tuning and Extending Rules](#tuning-and-extending-rules)
- [Dask Monitoring & Task Management](#dask-monitoring--task-management)
- [Testing and Quality Assurance](#testing-and-quality-assurance)
- [Version Information](#version-information)


---

## Quick Start

The **Orochi Admin Interface** allows administrators to:

- Manage users and permissions
- Configure and monitor Volatility plugins
- Enable services like **ClamAV**, **VirusTotal**, and **MISP**
- Maintain YARA rule sets and Dask worker nodes

### Default Access

- Default superuser: `admin`
- Default password: `admin`

⚠️ **Important:** Change the default password immediately after the first login.

To create additional superusers:

```bash
docker-compose run --rm django python manage.py createsuperuser
```

Then access the admin dashboard:

👉 [https://localhost/admin](https://localhost/admin)

![sign-in](images/023_admin_sign_in.png)
![admin-home](images/024_admin_home.png)

---

## Concepts

The **Orochi Admin Interface** provides centralized management for the Volatility-based analysis environment.  
Through this panel, administrators can:

- Customize default plugin behavior
- Manage users, dumps, and extracted files
- Enable external integrations (VirusTotal, MISP, ClamAV)
- Maintain plugin and symbol databases
- Update and distribute YARA rulesets

---

## Login

Access the admin dashboard via Nginx at:

👉 [https://localhost/admin](https://localhost/admin)

Use the default credentials or your created superuser account.  
Once logged in, you’ll have full control over all administrative functions.

---

## Account Management

### Email Addresses

Monitor user registration and verification status here.  
Admins can manually validate users’ email addresses when needed.

![admin-email](animations/admin_email.gif)

### Users

View, edit, and remove registered users.  
You can modify permissions or reset passwords directly from this section.

![admin-users](images/027_admin_users.png)
![admin-users-edit](images/028_admin_users_edit.png)

---

## Website Management

This area lets administrators control all web-related data objects within Orochi, including dumps, plugins, and results.

### Dumps

View, edit, or delete all memory dumps uploaded by users.

![admin-dumps](images/029_admin_dumps.png)
![admin-dumps-edit](images/030_admin_dumps_edit.png)

### Extracted Dumps

In earlier versions of Orochi, files dumped by Volatility plugins (such as `windows.dumpfiles`) were tracked in a standalone `ExtractedDump` table.

> [!NOTE]
> In Orochi v2.5+, dumped executables and extracted artifacts are linked directly to Dump records, Plugin Results, and Case Evidence, allowing seamless file downloads, VirusTotal inspection, and ClamAV scanning without requiring separate database management.

### Plugins

View and configure all available Volatility plugins.  
Set global behaviors — for example, enabling **ClamAV** for all dumped files from a plugin such as `windows.pslist`.

![admin-plugin](images/033_admin_plugins.png)
![admin-plugin-edit](images/034_admin_plugins_edit.png)

### Results

Review the results of Volatility plugin executions.  
Errors are displayed under **Description**, and plugin parameters are visible under **Parameters**.

![admin-results](images/035_admin_results.png)
![admin-results-edit](images/036_admin_results_edit.png)

### Services

Orochi supports modular integrations with threat intelligence feeds, local generative AI models, and outbound notification pipelines. Services are managed under **WEBSITE -> Services** (`/admin/website/service/`).

![admin-services](images/037_admin_services.png)
![admin-services-add](images/038_admin_services_add.png)
![admin-services-types](images/075_admin_services_types.png)

> 📖 **Full Reference:** For deep architectural diagrams, JSON payload schemas, and automation scripts, see the [Services and MaxMind Configuration Guide](Services-and-MaxMind-Guide.md).

#### VirusTotal
Automatically calculates the SHA-256 hash of executables and dumped artifacts produced by Volatility plugins (such as `windows.dumpfiles`, `windows.malfind`, and `windows.procdump`) and queries VirusTotal.
- **Form Fields:**
  - **Name:** `VirusTotal`
  - **Key:** Your VirusTotal API Key
  - **Url:** Optional (e.g. `https://www.virustotal.com/api/v3` or blank)
  - **Proxy:** Optional JSON proxy configuration
- **Plugin Requirement:** Enable the `vt_check` checkbox on desired plugins in **WEBSITE -> Plugins**.
- ⚠️ **Rate Limit Notice:** Free public API keys are restricted to 4 requests/min (500/day). If a plugin dumps dozens of executables simultaneously, you may experience `QuotaExceededError`. Use an enterprise key or selectively enable `vt_check` only on malicious detection plugins like `windows.malfind`.

#### MISP
Enables analysts to export extracted memory artifacts, dumped files, and associated threat intelligence directly to a remote MISP instance.
- **Form Fields:**
  - **Name:** `MISP`
  - **Url:** Base URL of your MISP instance (e.g. `https://misp.cyber.local`)
  - **Key:** MISP User AuthKey (API Key)
  - **Proxy:** Optional JSON proxy configuration
- **Features:**
  - Creates a dedicated MISP event: `From orochi: <plugin>@<dump_name>`.
  - Attaches the dumped executable via `FileObject`.
  - Automatically correlates and attaches ClamAV `av-signature` objects (`attributed-to`) and VirusTotal scan permalinks.
- 💡 **Note:** SSL certificate verification is disabled by default in Orochi (`verifycert=False`) to accommodate private internal MISP instances with self-signed certificates.

#### Ollama
Enables private, on-premise generative AI executive summaries for digital forensic investigations in the Case Workspace (`/case/<pk>/report`).
- **Form Fields:**
  - **Name:** `Ollama`
  - **Url:** `http://ollama:11434` (internal Docker network) or external host URL
  - **Key:** **Model Name** (e.g. `llama3`, `mistral`, `qwen2.5:7b`). Defaults to `llama3` if left blank.
  - **Proxy:** Leave blank
- **Docker Compose Profile:**  
  Ollama is configured under the `[ "ollama" ]` Docker Compose profile. Start it using:
  ```bash
  docker-compose --profile ollama up -d ollama
  ```
- **Managing Models (Add / List / Remove):**
  - **Pull / Add Model:**
    ```bash
    docker exec -it orochi_ollama ollama pull llama3
    # Or pull other models:
    docker exec -it orochi_ollama ollama pull mistral
    docker exec -it orochi_ollama ollama pull qwen2.5:7b
    ```
  - **List Models:**
    ```bash
    docker exec -it orochi_ollama ollama list
    ```
  - **Test Model:**
    ```bash
    docker exec -it orochi_ollama ollama run llama3 "Hello, are you operational?"
    ```
  - **Remove Model:**
    ```bash
    docker exec -it orochi_ollama ollama rm mistral
    ```
- 💡 **Key Mapping Tip:** Orochi uses the **`Key`** field in the admin form as the model name passed to `/api/generate`. If you pull a model other than `llama3.2:1b`, update the `Key` field to match that model's exact tag.
- 📋 **Automated Forensic Reports:** When analysts request a case report (`/cases/`) with AI enabled, Orochi prompts Ollama to produce an executive triage narrative that is rendered directly in custom HTML/Jinja report templates (providing `{{ ai_summary }}` and `{{ ai_summary_html }}`). See [Services and MaxMind Guide](Services-and-MaxMind-Guide.md#forensic-case-executive-summaries) for template syntax and context schema.
- 🧠 **AI First-Pass Triage Narrative Engine:**
  - Orochi utilizes Ollama to provide executive first-pass triage narratives over structured plugin results (`TriageFinding`, `DumpSecret`, `PsList`, `NetScan`, `Malfind`, `CmdLine`, `Bash`).
  - **Chain-of-Custody Safeguards**: All inference is strictly on-premise. The evidence payload is hashed using SHA-256 before inference, and results are recorded in the `DumpNarrative` model with model name and evidence hash.
  - **Algorithmic Guardrails (Anti-Hallucination)**: Orochi deterministically verifies all asserted PIDs and memory offsets in the model response against genuine plugin records. Any fabricated PID or offset is immediately flagged with warning badges (`⚠️ Unverified PID: XXX`).
  - **Citations**: Findings cite exact plugin records (`[TriageFinding:ID]`, `[DumpSecret:ID]`, `[Value:ID]`), which are rendered as interactive inspection badges.
  - **REST API Endpoints**:
    - `GET /api/dumps/{index}/narrative`: Retrieve the latest triage narrative and verification status.
    - `POST /api/dumps/{index}/narrative/generate`: Generate a new narrative on demand with an optional model parameter.

#### Webhook
Sends outbound HTTP POST notifications to third-party endpoints, SIEMs, or SOAR platforms (e.g. Shuffle, Tines, n8n) when dumps or tasks finish.
- **Form Fields:**
  - **Name:** `Webhook`
  - **Url:** Destination endpoint URL (e.g. `https://soar.internal/webhook/orochi`)
  - **Key:** Optional Bearer Token. If provided, Orochi sends `Authorization: Bearer <key>`.
  - **Proxy:** Optional JSON proxy configuration
- **User Preference:** Analysts must enable `notify_via_webhook` in their account profile (`/users/notifications/`).

#### Slack
Posts real-time formatted notifications to a designated Slack channel.
- **Form Fields:**
  - **Name:** `Slack`
  - **Url:** Slack Incoming Webhook URL (`https://hooks.slack.com/services/...`)
  - **Key:** Unused
  - **Proxy:** Optional JSON proxy configuration
- **User Preference:** Analysts must enable `notify_via_slack` in their account profile (`/users/notifications/`).

#### Email
Dispatches notification emails when memory dump analysis or tasks complete.
- **Form Fields:**
  - **Name:** `Email`
  - **Url:** Destination email address (e.g. `soc-team@corp.local`). If left blank, Orochi falls back to the analyst's registered account email.
  - **Key:** Unused
  - **Proxy:** Unused
- **Mail Server Configuration:** Uses Django's configured SMTP settings (`settings.DEFAULT_FROM_EMAIL`, Mailpit at `http://localhost:8025` in development, or corporate SMTP relay).
- **User Preference:** Analysts must enable `notify_via_email` in their account profile (`/users/notifications/`).

#### Proxy Configuration
All services support routing through corporate HTTP/HTTPS proxy servers. Set the **Proxy** field to a valid JSON dictionary:

```json
{
  "http": "http://proxy.corp.internal:8080",
  "https": "http://proxy.corp.internal:8080"
}
```

Or with authentication:

```json
{
  "http": "http://user:password@proxy.corp.internal:8080",
  "https": "http://user:password@proxy.corp.internal:8080"
}
```

### User Plugins

Admins can manage which plugins run automatically for specific users.  
For example, enabling **Timeliner** for user2 ensures it runs by default on all of their dumps.

![admin-plugins](images/039_admin_plugins.png)
![admin-plugins-edit](images/040_admin_plugins_edit.png)

### Granular Role-Based Access Control (RBAC) & Plugin Permissions

Orochi introduces a standardized **Role-Based Access Control (RBAC)** architecture combined with **per-plugin permissions** and **per-user granular overrides**, balancing multi-tenant collaboration with least-privilege security.

![user-plugin-permissions](images/081_user_plugin_permissions.png)

#### 1. Standard User Roles & Hierarchy
Orochi defines four distinct operational roles with cascading capability levels:

| Role | Hierarchy Level | Capabilities & Boundaries |
| :--- | :---: | :--- |
| **Admin** | Level 3 | Full administrative authority. Unrestricted plugin execution (including disk-heavy memory dumpers and VAD scanners), symbol management, plugin installation, dump deletion, and user role administration. |
| **Analyst** | Level 2 | Standard forensic investigator. Can upload dumps, execute default and analyst-tier plugins (`PsList`, `NetScan`, `Malfind`, etc.), add row annotations, and evaluate triage findings. |
| **Reviewer** | Level 1 | Auditor / Junior investigator. Read-only dump inspection with authorization to run safe, non-invasive informational plugins (e.g., `windows.info.Info`). Blocked from running heavy or dumping plugins. |
| **ReadOnly** | Level 0 | Pure audit access. Can view plugin results, cases, and timelines, but strictly forbidden from triggering any plugin execution, uploading dumps, or editing data. |

#### 2. Per-Plugin Minimum Role (`min_role`)
Each Volatility plugin in Orochi defines a `min_role` attribute:
- **`Admin`**: Heavy disk, process extraction, or intensive scanner plugins (such as `windows.dumpfiles.DumpFiles`, `windows.memmap.Memmap`, and `windows.vadyarascan.VadYaraScan`).
- **`Analyst`** *(Default)*: Standard operational analysis plugins (`windows.pslist.PsList`, `windows.netscan.NetScan`, `windows.malfind.Malfind`, `linux.bash.Bash`, etc.).
- **`Reviewer`**: Low-overhead diagnostic plugins (`windows.info.Info`).

Administrators can customize `min_role` for any plugin in **WEBSITE -> Plugins** (`/admin/website/plugin/`) or via the REST API (`PUT /api/plugins/{name}`).

#### 3. Granular Per-User Overrides (`can_execute`)
Organizations frequently have senior analysts who require temporary or selective access to specific admin plugins without granting full superuser status. Orochi supports per-user overrides on `UserPlugin`:
- **`None` (Inherit Role Default)**: Plugin execution follows the user's role hierarchy vs `plugin.min_role`.
- **`True` (Explicitly Allowed)**: Grants execution authorization to this specific user regardless of role.
- **`False` (Explicitly Denied)**: Revokes execution authorization from this specific user even if their role would otherwise permit it.

#### 4. UI & Enforcement Matrix
- **Sidebar Plugin Component (`<orochi-plugin>`)**: Restricted plugins display a lock badge (`fa-lock`) with tooltip indicating minimum role required. Clicking a restricted plugin shows an informative alert.
- **Action Buttons (`partial_note.html`)**: The "Rerun" button is replaced with a locked badge if the user lacks execution permission.
- **Parameter Modal (`/parameters`)**: Returns HTTP 403 Forbidden if accessed without proper role or override.
- **Dask Plugin Dispatcher (`/api/dumps/{pks}/plugin/{plugin}/execute`)**: Hard enforcement before queuing tasks to Celery/Dask workers.

---

## Updating and Maintenance

### Update Plugins

Synchronize the Orochi framework with all available Volatility plugins.

Run:

```bash
docker-compose run --rm django python manage.py plugins_sync
```

![admin-update-plugins](images/041_admin_update_plugins.png)

Example log output:

```
django_1 | No plugins in db
django_1 | Available Plugins:
django_1 | Plugin windows.statistics.Statistics added!
...
django_1 | Plugin windows.pslist.PsList added to admin!
```

💡 **Tip:** Use this after upgrading Volatility or adding new custom plugins.

---

### Update Symbols

Checks for and downloads new symbol files from the Volatility Foundation website.

Run:

```bash
docker-compose run --rm django python manage.py symbols_sync
```

![admin-update-plugins](images/042_admin_update_symbols.png)

Example log:

```
django_1 | Remote hash: {'windows.zip': '...', 'mac.zip': '...', 'linux.zip': '...'}
django_1 | Downloading updated symbol sets...
django_1 | Updating local hashes
```

#### Web Symbols Management Hub (`/list_symbols`)

In addition to CLI sync, administrators and analysts can manage Volatility symbols directly via the web interface:
- **Browse Symbol Inventory**: Navigate to **Symbols** in the top navigation bar to view all loaded Windows, Linux, and macOS ISF symbol tables.
- **Upload Symbol Files**: Upload individual symbol `.json` or `.json.xz` files (`/upload_symbols`).
- **Upload Symbol Packages**: Upload `.zip` bundles containing multiple kernel symbol files (`/upload_packages`).
- **Download Remote ISF**: Ingest Intermediate Symbol Format (ISF) tables from custom ISF server URLs (`/download_isf`).

![symbols-management-hub](images/073_symbols_hub.png)

⚠️ **Connection Error Tip:**  
If you encounter DNS issues such as:

```
requests.exceptions.ConnectionError: ... Failed to establish a new connection ...
```

Edit `/etc/docker/daemon.json` to include:

```json
{ "dns": ["8.8.8.8", "8.8.4.4"] }
```

---

### Add Custom Plugins

You can upload **custom Volatility plugins** directly from the admin panel.

![add-custom-plugins](images/055_add_custom_plugin_.png)
![add-custom-plugins](images/056_add_custom_plugin_upload.png)

#### Supported Format

Only **ZIP archives** are supported.  
A valid ZIP must include at least one `.py` plugin file following Volatility’s folder structure.

Example schema:

![add-custom-plugins](images/057_add_custom_plugin_zip.png)

If additional dependencies are required, include:

- `requirements.txt` — Python libraries to install with pip
- `run.sh` — System-level dependencies to install via apt

After upload, the plugin becomes available to all users:

![run-custom-plugins](images/058_add_custom_plugin_ui.png)
![run-custom-plugins](images/059_add_custom_plugin_result.png)

---

### Update Vendored Libraries

Orochi vendors its third-party frontend JavaScript and CSS assets locally (e.g. **DataTables**, **Marked**, **SweetAlert2**, **TomSelect**, **HTMX**, and **JSZip**) to ensure the platform operates completely offline with zero external runtime CDN dependencies and without requiring Node.js or npm installed on the server.

To inspect, verify, and update these libraries safely without breaking functionality, administrators can use the built-in management command:

#### Check for Available Updates

Queries the public npm registry for the latest releases without modifying any local files:

```bash
docker-compose exec django_wsgi python manage.py update_vendor_js --check
```

Example output:
```
--- Checking Vendor JS/CSS Updates ---
Package                Current      Latest       Status
-------------------------------------------------------
datatables             2.1.4        3.0.3        Update available: 3.0.3
datatables-buttons     3.1.2        4.0.2        Update available: 4.0.2
datatables-checkboxes  1.3.0        1.3.0        Up to date
htmx                   2.0.4        2.0.10       Update available: 2.0.10
jszip                  3.10.1       3.10.1       Up to date
marked                 17.0.1       18.0.11      Update available: 18.0.11
sweetalert2            11.26.25     11.26.25     Up to date
tom-select             2.4.3        2.6.2        Update available: 2.6.2
```

#### Safe Update Modes

Update a single package:
```bash
docker-compose exec django_wsgi python manage.py update_vendor_js --package marked --update
```

Test a dry run before writing changes to disk:
```bash
docker-compose exec django_wsgi python manage.py update_vendor_js --package marked --update --dry-run
```

Pin or test a specific library version:
```bash
docker-compose exec django_wsgi python manage.py update_vendor_js --package marked --version-override 18.0.11 --update
```

Update all packages in one pass:
```bash
docker-compose exec django_wsgi python manage.py update_vendor_js --update
```

Roll back previously updated files from automatic `.bak` backups:
```bash
docker-compose exec django_wsgi python manage.py update_vendor_js --rollback
```

#### Safety & Corruption Protection
- **Pre-flight Integrity Validation**: Files are downloaded to memory and verified for HTTP 200, minimum byte length, and required export/token signatures (e.g., `marked.parse`, `DataTable`, `Swal`, `TomSelect`).
- **Atomic Swap with Automatic Backups**: Working files are backed up to `.bak`, new files are written to `.tmp`, and swapped atomically using `os.replace`.
- **Zero-Corruption Guarantee**: If a network error occurs or a CDN file fails validation, the operation halts immediately, leaving the working files completely intact.
- **Manifest Tracking**: Pinned versions, download URLs, and integrity signatures are tracked in [`orochi/static/vendor_manifest.json`](file:///home/dadokkio/Docker/NOSTRI/orochi/orochi/static/vendor_manifest.json).

---

### MaxMind GeoIP Configuration

Orochi leverages **MaxMind GeoLite2** binary database files (`.mmdb`) to provide IP geolocation, city mapping, and Autonomous System Number (ASN) intelligence for network forensic plugins (such as `windows.netscan`, `windows.netstat`, and `linux.sockstat`) and the Temporal Diff timeline view.

#### Required Database Files
Place the following `.mmdb` files into `compose/local/maxmind/`:
- `GeoLite2-ASN.mmdb` — Autonomous System Numbers and ISP names
- `GeoLite2-City.mmdb` — Cities, administrative regions, and geographic coordinates
- `GeoLite2-Country.mmdb` — ISO country codes and full country names

#### Downloading from MaxMind
Due to MaxMind's licensing agreement, these databases must be downloaded after creating an account:
1. Register for free at [MaxMind GeoLite2 Sign Up](https://www.maxmind.com/en/geolite2/signup).
2. Generate a License Key in your MaxMind portal.
3. Download the Gzip/Tar archives from [MaxMind GeoIP Downloads](https://www.maxmind.com/en/accounts/current/geoip/downloads).
4. Extract the `.mmdb` files into `compose/local/maxmind/`.

#### Zero-Rebuild Volume Mount (Recommended)
By default, Dockerfiles copy `./compose/local/maxmind` into `/maxmind` at image build time. To update your databases in production without rebuilding Docker images, add a read-only bind mount to `django_wsgi`, `django_asgi`, and `worker` in `docker-compose.yml`:

```yaml
    volumes:
      # ... other existing volumes ...
      - ./compose/local/maxmind:/maxmind:ro
```

When new database files are dropped into `compose/local/maxmind/` on the host, Orochi immediately utilizes the updated databases.

#### Enabling MaxMind in Plugins
1. Open the Admin panel at `https://localhost/admin`.
2. Go to **WEBSITE -> Plugins** (`/admin/website/plugin/`).
3. Filter by network plugins (e.g., `windows.netscan.NetScan`).
4. Ensure the **Maxmind check** (`maxmind_check`) checkbox is enabled.

#### Verification
Test the endpoint inside the running container:
```bash
docker-compose exec django_wsgi curl -k -u admin:admin "https://localhost/api/utils/maxmind?ip=8.8.8.8"
```
When viewing network plugin outputs in the web UI, external IP columns display interactive map pin buttons (`<i class="fa-solid fa-map-location"></i>`) that pop up geolocation, ISP, and ASN metadata.

> 📖 **Deep Dive:** For step-by-step automation using `geoipupdate` cron jobs and REST API schemas, consult the [Services and MaxMind Configuration Guide](Services-and-MaxMind-Guide.md).

---

## YARA Rules Management

Administrators can fully manage YARA rule sets through the admin interface.

![yara-admin](images/062_yara_admin.png)

### Update Rules

Press **Update Rules** to download rule collections from  
[Awesome YARA](https://github.com/InQuest/awesome-yara).

### Generate Default Rule

Press **Generate Default Rule** to compile a base ruleset using all currently enabled rules.

### Manage Rules

View all system rules and enable or disable them as needed.

![yara-admin-rules](images/063_yara_admin_rules.png)

### Manage Rulesets

View and toggle entire YARA rulesets.

![yara-admin-ruleset](images/064_yara_admin_ruleset.png)

### Curated Secrets Ruleset (`secrets.yar`)

Orochi includes an optimized, curated YARA ruleset specifically engineered to discover exposed credentials, API keys, private keys, and authentication tokens in physical and virtual process memory:

- **File Location**: `orochi/website/rules/secrets.yar`
- **Engine**: Powered by high-speed **YARA-X** scanning via `orochi/website/secrets_scanner.py`.
- **Target Surfaces**:
  - Raw uncompressed memory dump bytes.
  - Parsed string outputs across all executed Volatility plugins (e.g. `cmdline`, `strings`, `envars`).
- **Covered Pattern Categories**:
  - **AWS**: Access Key IDs (`AKIA...`, `ASIA...`) and Secret Access Keys.
  - **Azure**: Management tokens, SAS signatures, and storage account keys.
  - **Google Cloud (GCP)**: Service account private key JSON payloads and OAuth access tokens.
  - **Private Cryptographic Keys**: RSA, DSA, EC, and OpenSSH private keys (`BEGIN RSA PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`).
  - **JWT Tokens**: RFC 7519 JSON Web Tokens (`eyJh...`, `eyJb...`).
  - **Chat & Webhook Credentials**: Slack Bot tokens (`xoxb-`), Incoming Webhook URLs, and Discord bot tokens.
  - **Database Connection URIs**: Standard connection strings containing credentials (`postgres://`, `mysql://`, `mongodb://`).
  - **High-Entropy Generic Secrets**: Heuristic matching for high-entropy API tokens, bearer headers, and credential strings.

Administrators can edit or append custom organizational patterns directly to `orochi/website/rules/secrets.yar`. The changes take effect immediately on subsequent scans without requiring a server reboot.

---

## Forensic Behavioral Detection & Triage Engine

Orochi contains a declarative **Forensic Behavioral Detection & Triage Engine** that evaluates suspicious patterns and system anomalies directly across structured Volatility 3 outputs (`orochi/website/detection/rules.py` and `orochi/website/detection/engine.py`).

### Detection Rule Architecture
Unlike raw string scanning, the detection engine processes normalized relational and structured JSON rows generated by Volatility plugins (`pslist`, `pstree`, `psscan`, `malfind`, `netscan`, `cmdline`, `privileges`), correlating cross-plugin observations to uncover stealthy attacker actions.

### Core Forensic Detection Rules

| Rule ID | Rule Name | Category | Severity | Score | MITRE ATT&CK | Description |
| ------- | --------- | -------- | -------- | ----- | ------------ | ----------- |
| `PROC_INCOHERENT_PARENT_SVCHOST` | Incoherent svchost.exe Parent | Process Tree | Critical | +40 | T1036.005 | `svchost.exe` was spawned by a process other than `services.exe` (e.g. `cmd.exe`, `explorer.exe`). |
| `PROC_INCOHERENT_PARENT_SMSS` | Incoherent smss.exe Parent | Process Tree | Critical | +40 | T1036.005 | `smss.exe` was spawned by an unexpected parent process instead of `System` (PID 4). |
| `PROC_INCOHERENT_PARENT_SERVICES` | Incoherent services.exe Parent | Process Tree | Critical | +40 | T1036.005 | `services.exe` parent process is not `wininit.exe`. |
| `PROC_INCOHERENT_PARENT_LSASS` | Incoherent lsass.exe Parent | Process Tree | Critical | +40 | T1003.001 | `lsass.exe` parent is not `wininit.exe` (indicates credential dumping / spoofing). |
| `PROC_DKOM_UNLINKED` | DKOM Process Unlinking (Rootkit) | Stealth / DKOM | Critical | +50 | T1014 | Process was discovered in physical memory (`psscan`) but is unlinked from active process list (`pslist`). |
| `MEM_MALFIND_PE_INJECTED` | Injected Executable PE Header | Memory Injection | Critical | +40 | T1055.002 | Unbacked `PAGE_EXECUTE_READWRITE` memory region containing embedded `MZ` DOS/PE headers. |
| `MEM_MALFIND_RWX_INJECTION` | Unbacked RWX Injected Memory | Memory Injection | High | +25 | T1055 | Memory region with execute-read-write protection lacking backing file on disk. |
| `CMD_POWERSHELL_OBFUSCATED` | Obfuscated PowerShell Command | LOLBins | High | +30 | T1059.001 | PowerShell executed with execution bypass or encoded switches (`-enc`, `-w hidden`, Base64). |
| `PRIV_SE_DEBUG_ENABLED` | Suspicious SeDebugPrivilege | Privilege Escalation | Medium | +15 | T1078 | `SeDebugPrivilege` enabled on non-system / interactive user process. |

### Cumulative Risk Scoring & Severity Thresholds
When detection rules trigger on a dump, Orochi calculates a cumulative risk score:
$$\text{Risk Score} = \min(100, \sum \text{Finding Weights})$$

The overall dump health is categorized into five risk tiers:
- **Critical Risk (75 - 100)**: Active intrusion, DKOM rootkit, or code injection identified.
- **High Risk (50 - 74)**: Highly anomalous process relationships or obfuscated script executions.
- **Medium Risk (25 - 49)**: Suspicious privilege adjustments or unverified connections.
- **Low Risk (1 - 24)**: Minor heuristic indicators.
- **Clean (0)**: Baseline behavior; no anomalies detected.

### Tuning and Extending Rules
To implement new detection rules:
1. Define a new `DetectionRule` in `orochi/website/detection/rules.py`:
   ```python
   DetectionRule(
       id="NET_SUSPICIOUS_TOR_PORT",
       name="Connection to Tor Port",
       category="Network",
       severity="High",
       score=30,
       mitre_technique="T1071.001",
       plugin_dependencies=["windows.netscan.NetScan"],
       evaluator=check_tor_ports,
   )
   ```
2. Implement the evaluator function accepting `dump` or plugin result rows.
3. Tests can be added in `orochi/website/tests/test_detection_engine.py`.

---

## Dask Monitoring & Task Management

Orochi provides two complementary ways to monitor and control background operations:

### 1. Dask Dashboard
The official **Dask Bokeh Dashboard** is integrated into Orochi for cluster-level diagnostics:
1. Click the **Admin** icon in the navigation bar.
2. Select **Dask Status** (or navigate directly to `http://localhost:8787`).
3. View real-time cluster metrics, worker CPU/memory graphs, and task stream waterfalls.

![dask-monitoring](images/0068_dask_monitoring.png)

### 2. Integrated Activity Drawer & Task Management API
Administrators and analysts can also inspect and control tasks directly through the UI without leaving their investigation:

- **Cluster Correlation (`/api/utils/dask_status`)**:
  Maps raw Dask scheduler keys to corresponding Django models, exposing:
  - File ingestions (`manage_upload`)
  - Compressed memory extractions (`unzip`)
  - Volatility plugin runs (`run_plugin`)
  - Maintenance jobs (`TaskLog`)
- **Forensic Task Inspection (`GET /api/utils/tasks/info/{task_id}`)**:
  Returns comprehensive runtime diagnostics including assigned worker node, elapsed runtime duration, dump operating system/index, input parameters, and standard error/traceback.
- **Task Termination & Cancellation (`POST /api/utils/tasks/kill/{task_id}`)**:
  Cancels the underlying Dask future with `client.cancel(future, force=True)`, cleanly marks the corresponding dump or result as `Cancelled by user`, and immediately frees worker concurrency slots. Non-admin users can cancel their own jobs; superusers can cancel any task or raw scheduler key.
- **Transaction-Resilient Task Logging**:
  Background task logs (`TaskLog`) use resilient database transaction retries to avoid lock contention under heavy concurrency and broadcast completion notifications to administrators via WebSockets.

---

## Testing and Quality Assurance

Orochi maintains a comprehensive automated test suite powered by **pytest** and **pytest-django** covering models, API routers, background Dask task interfaces, template rendering, and frontend asset integrity.

### Running the Test Suite

Execute tests inside the running Django container:

```bash
# Run all tests
docker-compose exec django_wsgi pytest

# Run with verbose output and duration profiling
docker-compose exec django_wsgi pytest -v --durations=10
```

### Running Specific Test Modules

```bash
# Test vendored JS/CSS integrity, CDN signatures & update management command
docker-compose exec django_wsgi pytest orochi/website/tests/test_vendor_assets.py

# Test website UI views, DataTables styling, and HTMX swap dynamics
docker-compose exec django_wsgi pytest orochi/website/tests/test_ui_views.py

# Test API endpoints (Dumps, Tasks, Folders, Cases, Rules, Symbols)
docker-compose exec django_wsgi pytest orochi/api/tests/

# Test Volatility Dask utilities & timeliner
docker-compose exec django_wsgi pytest orochi/website/tests/test_utilities.py
```

### Continuous Verification
Every pull request and commit is automatically verified via GitHub Actions for test pass rates, linting (`flake8`, `black`), and CodeQL security analysis.

---

## Version Information

- **Application:** Orochi v2.5.0
- **Frameworks:** Django, Dask, Volatility 3
- **License:** MIT
- **Repository:** [https://github.com/LDO-CERT/orochi](https://github.com/LDO-CERT/orochi)

---

© 2026 LDO-CERT — Administrative Management Manual

