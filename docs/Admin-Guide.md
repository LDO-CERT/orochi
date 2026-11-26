# Orochi Admin Guide

_Administrative Management and Maintenance Manual_

---

## Table of Contents

- [Orochi Admin Guide](#orochi-admin-guide)
  - [Table of Contents](#table-of-contents)
  - [Quick Start](#quick-start)
    - [Default Access](#default-access)
    - [Settings Modules & Environment](#settings-modules--environment)
    - [Runtime Settings (Extra Settings)](#runtime-settings-extra-settings)
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
      - [Symmetric Secrets Encryption (AES-256-GCM)](#symmetric-secrets-encryption-aes-256-gcm)
      - [VirusTotal](#virustotal)
      - [MISP](#misp)
      - [Ollama](#ollama)
      - [Webhook](#webhook)
      - [Slack](#slack)
      - [Email](#email)
      - [Threat Intelligence, SIEM, TheHive \& CAPE Sandbox Services](#threat-intelligence-siem-thehive--cape-sandbox-services)
      - [Proxy Configuration](#proxy-configuration)
    - [User Plugins](#user-plugins)
    - [Granular Role-Based Access Control (RBAC) \& Plugin Permissions](#granular-role-based-access-control-rbac--plugin-permissions)
      - [1. Standard User Roles \& Hierarchy](#1-standard-user-roles--hierarchy)
      - [2. Per-Plugin Minimum Role (`min_role`)](#2-per-plugin-minimum-role-min_role)
      - [3. Granular Per-User Overrides (`can_execute`)](#3-granular-per-user-overrides-can_execute)
      - [4. UI \& Enforcement Matrix (`role_required` 403 Behavior)](#4-ui--enforcement-matrix-role_required-403-behavior)
  - [Updating and Maintenance](#updating-and-maintenance)
    - [Update Plugins](#update-plugins)
    - [Update Symbols](#update-symbols)
      - [Web Symbols Management Hub (`/list_symbols`)](#web-symbols-management-hub-list_symbols)
      - [Remote ISF Banners \& Linux AArch64](#remote-isf-banners--linux-aarch64)
    - [Add Custom Plugins](#add-custom-plugins)
      - [Supported Format](#supported-format)
    - [Update Vendored Libraries](#update-vendored-libraries)
      - [Check for Available Updates](#check-for-available-updates)
      - [Safe Update Modes](#safe-update-modes)
      - [Safety \& Corruption Protection](#safety--corruption-protection)
    - [MaxMind GeoIP Configuration](#maxmind-geoip-configuration)
      - [Required Database Files](#required-database-files)
      - [Downloading from MaxMind](#downloading-from-maxmind)
      - [Zero-Rebuild Volume Mount (Recommended)](#zero-rebuild-volume-mount-recommended)
      - [Enabling MaxMind in Plugins](#enabling-maxmind-in-plugins)
      - [Verification](#verification)
    - [PostgreSQL Database Upgrades \& Backups](#postgresql-database-upgrades--backups)
    - [Fast Docker Startup Flags](#fast-docker-startup-flags)
    - [Release Gates](#release-gates)
    - [CTF Mode Administration](#ctf-mode-administration)
    - [Remote Object Storage (Experimental)](#remote-object-storage-experimental)
  - [YARA Rules Management](#yara-rules-management)
    - [Update Rules](#update-rules)
    - [Generate Default Rule](#generate-default-rule)
    - [Manage Rules](#manage-rules)
    - [Manage Rulesets](#manage-rulesets)
    - [Curated Secrets Ruleset (`secrets.yar`)](#curated-secrets-ruleset-secretsyar)
  - [Forensic Behavioral Detection \& Triage Engine](#forensic-behavioral-detection--triage-engine)
    - [Detection Rule Architecture](#detection-rule-architecture)
    - [Core Forensic Detection Rules](#core-forensic-detection-rules)
    - [Cumulative Risk Scoring \& Severity Thresholds](#cumulative-risk-scoring--severity-thresholds)
    - [Tuning and Extending Rules](#tuning-and-extending-rules)
  - [Dask Monitoring \& Task Management](#dask-monitoring--task-management)
    - [1. Dask Dashboard](#1-dask-dashboard)
    - [2. Integrated Activity Drawer \& Task Queue Management](#2-integrated-activity-drawer--task-queue-management)
  - [Testing and Quality Assurance](#testing-and-quality-assurance)
    - [Running the Test Suite](#running-the-test-suite)
    - [Running Specific Test Modules](#running-specific-test-modules)
    - [Additional CLI Management Commands](#additional-cli-management-commands)
    - [Continuous Verification](#continuous-verification)
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
docker compose run --rm django_wsgi python manage.py createsuperuser
```

Then access the admin dashboard:

👉 [https://localhost/admin](https://localhost/admin)

![sign-in](images/023_admin_sign_in.png)
![admin-home](images/024_admin_home.png)

### Settings Modules & Environment

`DJANGO_SETTINGS_MODULE` (in `.envs/.local/.django`) selects one of:

| Module | Use | Notes |
| --- | --- | --- |
| `config.settings.production` | Docker images, WSGI/ASGI servers, Dask workers (default) | `DEBUG=False`, cached template loader, Redis cache; with `HTTPS=True` session/CSRF cookies are `Secure` and `SECURE_HSTS_SECONDS` (default `0`) enables HSTS. |
| `config.settings.development` | Local development | `DEBUG=True`, template debug, Django Debug Toolbar and django-extensions when installed, passkeys over plain HTTP. Never expose it. |
| `config.settings.test` | `uv run pytest` | In-memory channels/cache, fast hashing; works without env files. |
| `config.settings.local` | Deprecated alias of `production` | Existing `.envs` files keep working; switch to `production`. |

Variables most often changed (all listed, with defaults, in `.envs/.local/.django.example`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | required | Signing and Service-key encryption secret (see [Symmetric Secrets Encryption](#symmetric-secrets-encryption-aes-256-gcm)). |
| `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS` | required / localhost set | Host names and origins served by Orochi. |
| `HTTPS`, `SECURE_HSTS_SECONDS` | `False`, `0` | HTTPS redirect, secure cookies and HSTS. |
| `ADMINS_EMAIL` | `ldo-cert@orochi.dev` | Comma separated recipients of error reports. |
| `DEFAULT_FROM_EMAIL`, `EMAIL_*` | `webmaster@localhost`, Mailpit | Outgoing mail. |
| `DEBUG_LEVEL`, `OROCHI_LOG_LEVEL` | `WARNING` | Log levels (root / Orochi loggers). |
| `USE_S3_STORAGE`, `AWS_*`, `STORAGE_CACHE_MAX_GB` | `False` | Remote dump storage (experimental). |
| `VOLATILITY_REMOTE_ISF_URL`, `REGIPY_PLUGINS`, `STORAGE_CACHE_MAX_GB`, `AUTO_RESOLVE_SYMBOLS`, `DUMP_RETENTION_DAYS`, `THREAD_NO`, `AWESOME_PATH`, `DEFAULT_YARA_RULE_PATH`, `VOLATILITY_SYMBOL_DOWNLOAD_PATH` | see below | **Initial values** of the runtime settings below. |

### Runtime Settings (Extra Settings)

**Admin › Extra settings** holds the settings you can change while Orochi runs: they are read when used, so a change applies to the next operation without restarting containers.

> [!IMPORTANT]
> The environment variable with the same name is only the **initial value**: the row is created on the first `migrate` and from then on the database value wins. Changing the variable in `.envs/.local/.django` later has no effect on an existing installation: edit the setting in the admin instead.

| Setting | Type | Takes effect | Meaning |
| --- | --- | --- | --- |
| `VOLATILITY_REMOTE_ISF_URL` | string | next plugin run / symbol check | Remote banners index used by Volatility to download Linux/Mac ISF on demand. Empty disables it (air-gapped). |
| `AUTO_RESOLVE_SYMBOLS` | bool | next upload with missing symbols | Download the debug package of an unknown Linux kernel, build its ISF and run the automatic plugins (see the Users Guide). Off by default. |
| `REGIPY_PLUGINS` | string | next HiveList run | Comma separated regipy plugins run on the registry hives of Windows dumps (e.g. `computer_name,host_domain_name,network_drives_plugin`). |
| `STORAGE_CACHE_MAX_GB` | int | next cache eviction | Local cache of remote (S3/MinIO) dumps; least recently used copies are evicted above it. `0` = never. |
| `DUMP_RETENTION_DAYS` | int | next purge | Days a deleted dump stays in the recycle bin (restorable, files kept) before it is purged. `0` = delete immediately, no recycle bin. Default `7`. |
| `THREAD_NO` | int | next YARA sync | Threads used to download and index YARA rulesets. |
| `AWESOME_PATH` | string | next YARA sync | URL of the awesome-yara README listing the public rulesets. |
| `DEFAULT_YARA_RULE_PATH` | string | next scan | Path of the compiled default YARA rule; after changing it, rebuild the rule (`python manage.py generate_default_rule`). |
| `VOLATILITY_SYMBOL_DOWNLOAD_PATH` | string | next symbol sync | Online folder of the Volatility symbol packs. |
| `CUSTOM_LOGO` | image | next page | Logo shown on the login page. |

Expired dumps are purged in the background after every deletion and whenever someone opens the Recycle Bin. To purge them also when nobody uses the UI (and free disk space on time), run the command from cron:

```bash
docker compose exec django_wsgi python manage.py purge_recycle_bin          # dumps past DUMP_RETENTION_DAYS
docker compose exec django_wsgi python manage.py purge_recycle_bin --days 1 # deleted more than 1 day ago
docker compose exec django_wsgi python manage.py purge_recycle_bin --all    # empty the recycle bin
```

YARA feeds marked **Auto update** (Admin › Rulesets) are synchronized by a command meant for cron; it only syncs a feed once per `--interval` hours and reports invalid or duplicate rules it skipped while rebuilding the default rule set:

```bash
# crontab: every hour, sync the auto-update feeds not synced in the last 24 hours
0 * * * * cd /opt/orochi && docker compose exec -T django_wsgi python manage.py yara_feeds_update --interval 24
```

Everything else (secrets, database/Redis/Dask, hosts and HTTPS, LDAP, SMTP, paths of folders and binaries, log levels, storage backend) is read at startup from the environment and needs a container restart.

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
Self-registration is **disabled by default**: users are created by an administrator (or via LDAP). Set `DJANGO_ACCOUNT_ALLOW_REGISTRATION=True` in `.envs/.local/.django` to open the sign-up page.  
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
> Dumped executables and extracted artifacts are linked directly to Dump records, Plugin Results, and Case Evidence, allowing seamless file downloads, VirusTotal inspection, and ClamAV scanning without requiring separate database management.

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

#### Symmetric Secrets Encryption (AES-256-GCM)
In Orochi all external service credentials (keys, tokens, passwords) are encrypted at rest in PostgreSQL using AES-256 in Galois/Counter Mode (GCM).
- **Key Derivation**: The AES key is the SHA-256 digest of Django's `SECRET_KEY` (`DJANGO_SECRET_KEY`, mandatory: the application refuses to start without it).
- **Key Rotation**: Put the old key in `DJANGO_SECRET_KEY_FALLBACKS`, set the new `DJANGO_SECRET_KEY`, restart and run `docker compose run --rm django_wsgi python manage.py reencrypt_service_keys`. Once it reports success, remove the fallback. A key that cannot be decrypted is treated as empty (and logged), never sent in its encrypted form.
- **Storage Format**: Encrypted strings are stored with the prefix `enc:<base64(nonce + tag + ciphertext)>`.
- **Transparent Decryption**: The application transparently decrypts keys upon access via the `Service.decrypted_key` property or `service.set_encrypted_key(raw_value)`. Existing plaintext keys are seamlessly migrated upon save.

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
- 💡 **Note:** TLS certificate verification is controlled per service via the **Verify ssl** (`Service.verify_ssl`) checkbox — enabled by default for newly created services, and disableable for internal MISP instances using self-signed certificates.

#### Ollama
Enables private, on-premise generative AI executive summaries for digital forensic investigations in the Case Workspace (`/case_report/<pk>`).
- **Form Fields:**
  - **Name:** `Ollama`
  - **Url:** `http://ollama:11434` (internal Docker network) or external host URL
  - **Key:** **Model Name** (e.g. `llama3`, `mistral`, `qwen2.5:7b`). Defaults to `llama3` if left blank.
  - **Proxy:** Leave blank
- **Docker Compose Profile:**  
  Ollama is configured under the `[ "ollama" ]` Docker Compose profile. Start it using:
  ```bash
  docker compose --profile ollama up -d ollama
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
- 🔒 **Local endpoints only:** the URL must point to a local or private host (`localhost`, `ollama`, `*.local`, `*.internal`, a loopback/private/link-local IP); any other host is refused, so dump evidence never leaves your network by mistake. To use a remote endpoint on purpose set `LLM_ALLOW_REMOTE_ENDPOINT=True` in `.envs/.local/.django` and restart.
- 🔒 **No raw identifiers in the narrative:** the displayed narrative never states PIDs, memory offsets or hashes outside a citation pill: the cited record carries them. The model's raw answer is still stored with the narrative, and its claims are verified (unverified values are counted in the integrity check).
- 💡 **Key Mapping Tip:** Orochi uses the **`Key`** field in the admin form as the model name passed to `/api/generate`. If you pull a model other than `llama3.2:1b`, update the `Key` field to match that model's exact tag.
- 📋 **Automated Forensic Reports:** When analysts request a case report (`/case/<pk>`) with AI enabled, Orochi prompts Ollama to produce an executive triage narrative that is rendered directly in custom HTML/Jinja report templates (providing `{{ ai_summary }}` and `{{ ai_summary_html }}`). See [Services and MaxMind Guide](Services-and-MaxMind-Guide.md#forensic-case-executive-summaries) for template syntax and context schema.
- 🧠 **AI First-Pass Triage Narrative Engine:**
  - Orochi utilizes Ollama to provide executive first-pass triage narratives over structured plugin results (`TriageFinding`, `DumpSecret`, `PsList`, `NetScan`, `Malfind`, `CmdLine`, `Bash`).
  - **Chain-of-Custody Safeguards**: Inference runs on the Ollama service configured in Admin › Services (the bundled container keeps data on premises; a remote host receives the evidence context). The evidence payload is hashed using SHA-256 before inference, and results are recorded in the `DumpNarrative` model with model name and evidence hash.
  - **Algorithmic Guardrails (Anti-Hallucination)**: Orochi checks every PID, memory offset, IPv4 address and hash quoted in the response against the evidence sent to the model; values not found are flagged with warning badges (`⚠️ Unverified PID: XXX`), and offsets quoted next to a PID they do not belong to are reported as misattributed. Other claims and conclusions are not checked.
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

#### Threat Intelligence, SIEM, TheHive & CAPE Sandbox Services
In addition to the core services above, Orochi supports six additional integrations under **WEBSITE -> Services**:
- **AbuseIPDB**, **AlienVault OTX**, and **GreyNoise**: Multi-source IOC enrichment inside the per-dump IOC Extraction Hub (`/dump/<index>/iocs`).
- **SIEM (Splunk HEC / Elastic / Sentinel)**: Forwards dump/task notifications and on-demand case summaries (`POST /api/cases/{id}/siem/forward`).
- **TheHive / Cortex**: Exports cases with findings as tasks, MITRE techniques as tags, and IOCs as observables (`POST /api/cases/{id}/export/thehive`).
- **CAPE / Cuckoo Sandbox**: Allows non-ReadOnly analysts to submit extracted dump files directly from plugin result rows, case evidence, or `POST /api/dumps/{index}/sandbox/submit`.

Use **Verify ssl** (`Service.verify_ssl`) to control TLS validation per service, and test live credentials via `POST /service/test-connection` or inspect masked runtime settings via `GET /api/admin/settings` (Superuser only). See the [Services and MaxMind Guide](Services-and-MaxMind-Guide.md) for full configuration tables.

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
Orochi defines four distinct operational roles with cascading capability levels (`orochi/website/roles.py`):

| Role         | Hierarchy Weight | Capabilities & Boundaries                                                                                                                                                                                                                                        |
| :----------- | :--------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Admin**    |       `40`       | Full administrative authority (`is_superuser` / `is_staff` or `Admin` group). Unrestricted plugin execution (including disk-heavy memory dumpers and VAD scanners), symbol management, plugin installation, dump deletion, and user role administration.         |
| **Analyst**  |       `30`       | Standard forensic investigator (default for users without an explicit role group). Can upload dumps, execute default and analyst-tier plugins (`PsList`, `NetScan`, `Malfind`, etc.), manage cases/playbooks, add row annotations, and evaluate triage findings. |
| **Reviewer** |       `20`       | Auditor / Junior investigator. Read-only dump inspection with authorization to run safe, non-invasive informational plugins (e.g., `windows.info.Info`). Blocked from running heavy or dumping plugins.                                                          |
| **ReadOnly** |       `10`       | Pure audit access. Can view plugin results, cases, and timelines, and participate as a **CTF Solver** in CTF-enabled cases, but strictly forbidden from triggering any plugin execution, uploading dumps, or editing data.                                       |

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

#### 4. UI & Enforcement Matrix (`role_required` 403 Behavior)
- **Web Views (`role_required` decorator)**: Unauthenticated requests are redirected to the login page; **authenticated** users who lack the required role (e.g., an `Analyst` requesting an Admin-only symbols upload endpoint, or a `ReadOnly` user requesting a write view) receive an explicit **HTTP 403 Forbidden** (`PermissionDenied`) instead of a login redirect loop.
- **Sidebar Plugin Component (`<orochi-plugin>`)**: Restricted plugins display a lock badge (`fa-lock`) with tooltip indicating minimum role required. Clicking a restricted plugin shows an informative alert.
- **Action Buttons (`partial_note.html`)**: The "Rerun" button is replaced with a locked badge if the user lacks execution permission.
- **Parameter Modal (`/parameters`)**: Returns HTTP 403 Forbidden if accessed without proper role or override.
- **Dask Plugin Dispatcher (`/api/dumps/{pks}/plugin/{plugin}/execute`)**: Hard enforcement before queuing tasks to Dask workers (returns `403 Forbidden`).

---

## Updating and Maintenance

### Update Plugins

Synchronize the Orochi framework with all available Volatility plugins.

Run:

```bash
docker compose run --rm django_wsgi python manage.py plugins_sync
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
docker compose run --rm django_wsgi python manage.py symbols_sync
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
- **Build DWARF / BTF ISF**: Compile Linux ISF `.json.xz` tables directly on Dask workers from unstripped `vmlinux` (`dwarf2json`) or lightweight BTF metadata (`/sys/kernel/btf/vmlinux` or stripped `vmlinux`) + `System.map` + kernel banner (`btf2json`).
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

#### Remote ISF Banners & Linux AArch64

- **Remote ISF banners**: volatility3 downloads Linux/macOS ISF files on demand from the banners index in `VOLATILITY_REMOTE_ISF_URL` (default: the `Abyss-W4tcher/volatility3-symbols` index). Set it to your own mirror, or to an empty value for air-gapped installations.
- **Linux AArch64 (ARM64) dumps & BTF ISF schema patch**: upstream volatility3 does not support Linux AArch64 or `btf2json` (`kind: "btf"`) schemas yet. The images patch volatility3 via `compose/local/vol_fix/apply.sh`: applying PR [#1088](https://github.com/volatilityfoundation/volatility3/pull/1088) merged with the current upstream `automagic/linux.py` (VMCOREINFO stacker and Linux specific Intel layers included), and extending `volatility3/schemas/schema-6.*.json` to allow `btf`/`symdb` metadata kinds. `apply.sh` stops the image build if the pinned volatility3 revision changes, so the merge is never silently lost. After bumping volatility3 in `pyproject.toml`, re-merge `vol_fix/linux.py` against the new upstream file and update the checksum in `apply.sh` (or drop the AArch64 files once #1088 is merged upstream).

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
docker compose exec django_wsgi python manage.py update_vendor_js --check
```

Example output:
```
--- Checking Vendor JS/CSS Updates ---
Package                Current      Latest       Status
-------------------------------------------------------
datatables             2.1.4        3.0.3        Update available: 3.0.3
datatables-buttons     3.1.2        4.0.2        Update available: 4.0.2
datatables-checkboxes  1.3.0        1.3.0        Up to date
htmx                   2.0.11       2.0.11       Up to date
jszip                  3.10.2       3.10.2       Up to date
marked                 18.1.2       18.1.2       Up to date
sweetalert2            11.26.25     11.26.25     Up to date
tom-select             2.4.3        2.6.2        Update available: 2.6.2
```

#### Safe Update Modes

Update a single package:
```bash
docker compose exec django_wsgi python manage.py update_vendor_js --package marked --update
```

Test a dry run before writing changes to disk:
```bash
docker compose exec django_wsgi python manage.py update_vendor_js --package marked --update --dry-run
```

Pin or test a specific library version:
```bash
docker compose exec django_wsgi python manage.py update_vendor_js --package marked --version-override 18.1.2 --update
```

Update all packages in one pass:
```bash
docker compose exec django_wsgi python manage.py update_vendor_js --update
```

Roll back previously updated files from automatic `.bak` backups:
```bash
docker compose exec django_wsgi python manage.py update_vendor_js --rollback
```

#### Safety & Corruption Protection
- **Pre-flight Integrity Validation**: Files are downloaded to memory and verified for HTTP 200, minimum byte length, and required export/token signatures (e.g., `marked.parse`, `DataTable`, `Swal`, `TomSelect`).
- **Atomic Swap with Automatic Backups**: Working files are backed up to `.bak`, new files are written to `.tmp`, and swapped atomically using `os.replace`.
- **Zero-Corruption Guarantee**: If a network error occurs or a CDN file fails validation, the operation halts immediately, leaving the working files completely intact.
- **Manifest Tracking**: Pinned versions, download URLs, and integrity signatures are tracked in [`orochi/static/vendor_manifest.json`](../orochi/static/vendor_manifest.json).

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
Test the endpoint from the host using a personal Bearer API token (generated via `POST /api/auth/tokens/`):
```bash
curl -k -H "Authorization: Bearer oro_your_token_here" "https://localhost/api/utils/maxmind?ip=8.8.8.8"
```
When viewing network plugin outputs in the web UI, external IP columns display interactive map pin buttons (`<i class="fa-solid fa-map-location"></i>`) that pop up geolocation, ISP, and ASN metadata.

> 📖 **Deep Dive:** For step-by-step automation using `geoipupdate` cron jobs and REST API schemas, consult the [Services and MaxMind Configuration Guide](Services-and-MaxMind-Guide.md).

### PostgreSQL Database Upgrades & Backups

Orochi stores investigation metadata, cases, evidence, bookmarks, IOCs, and task history in PostgreSQL. Because PostgreSQL major versions (e.g. 15, 16, 17) use incompatible on-disk data formats, upgrading the PostgreSQL version requires safe data migration.

Orochi provides automated host-level scripts under `scripts/postgres/`:
- **Automated Upgrade (`./scripts/postgres/upgrade_postgres.sh --to 17.4`)**: Automated zero-data-loss upgrade that performs pre-flight checks, quiesces application writers, exports a full cluster dump (`pg_dumpall`), clones a timestamped snapshot of the Docker volume, starts the target PostgreSQL version, restores data, runs `VACUUM ANALYZE`, verifies Django migrations, and handles automatic rollback on failure.
- **Host Backup (`./scripts/postgres/backup_postgres.sh`)**: Generates compressed, timestamped cluster backups (`.sql.gz`).
- **Host Restore (`./scripts/postgres/restore_postgres.sh <backup_file>`)**: Restores database backups with connection dropping and pre-restore snapshots.

> 📖 **Complete Upgrade Guide:** For detailed procedures, in-place `pg_upgrade --link` for large databases, manual upgrade walkthroughs, and disaster recovery, refer to the [PostgreSQL Version Upgrade & Maintenance Guide](Postgres-Upgrade-Guide.md).

---

### Fast Docker Startup Flags

The `django_wsgi` entrypoint (`compose/local/django/start`) exposes three environment flags to optimize container boot time:

| Variable                 | Default | Behavior                                                                                                                                                          |
| :----------------------- | :-----: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TAILWIND_REBUILD`       |   `0`   | Set to `1` to rebuild `orochi/static/css/tailwind_dist.css` on start. Defaults to `0` so production/air-gapped containers start offline using the baked CSS. |
| `COLLECTSTATIC_ON_START` |   `0`   | Only runs `collectstatic` when set to `1`, on first boot (missing `/app/staticfiles/.collectstatic.stamp`), or when static source files are newer than the stamp. |
| `TAILWIND_WATCH`         |   `0`   | Set to `1` during local UI development to spawn `python manage.py tailwind watch` in the background.                                                              |

> 💡 `docker-compose-swarm.yml` pre-configures `TAILWIND_WATCH=0` and `COLLECTSTATIC_ON_START=0` on `django_wsgi`.

### Release Gates

No image is published from `master` or a `v*` tag unless the `tests` job and the release gates in `.github/workflows/release-gates.yml` pass (#1670, #1672). The gates build the candidate django image once (linux/amd64) and run three checks: **offline-start** starts it with PostgreSQL and Redis on a `docker network create --internal` network (no Internet, `TAILWIND_REBUILD=1`) and requires `/accounts/login/` to answer 200 within 180 seconds; **fresh-install** brings up a fresh `docker compose` stack, creates an Analyst, a ReadOnly user and a second Analyst with `manage.py`, and uses the Python client (`clients/python`) to upload a small dummy file, read it back and read the plugin status as the Analyst, checking that the ReadOnly user cannot upload and the other Analyst cannot see the dump (no memory analysis runs); **upgrade-smoke** migrates and seeds a user, folder, dump, permission and plugin result with the previous release image (`ghcr.io/ldo-cert/orochi_django:<highest earlier v* tag>`, or the `previous_tag` input), migrates with the candidate image and checks that the seeded objects are still readable and the login page is served. Tag images are also signed keyless with cosign, besides the SBOM, provenance attestation and Trivy scan; verify a signature with `cosign verify ghcr.io/ldo-cert/orochi_django@<digest> --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github.com/LDO-CERT/orochi/.github/workflows/push.yml@refs/tags/v'`. To make the gates mandatory for pull requests, add `tests / test` and `release-gates / offline-start`, `release-gates / fresh-install`, `release-gates / upgrade-smoke` to the required status checks of the `master` branch protection.

### CTF Mode Administration

Superusers can manage graded training exercises in Django Admin under **WEBSITE**:
- **CTF questions** (`/admin/website/ctfquestion/`): create or edit Jeopardy questions and inline hints (with point costs). Answers are stored as SHA-256 hashes of the lowercased, trimmed plaintext and cannot be read back.
- **CTF objectives** (`/admin/website/ctfobjective/`): manage canonical ground-truth forensic discovery objectives (entity type, JSON criteria, MITRE ATT&CK bonus, points).
- **CTF submissions** (`/admin/website/ctfsubmission/`) & **CTF discovery submissions** (`/admin/website/ctfdiscoverysubmission/`): read-only audit trails of student answers, TP/FP/Duplicate verdicts, MITRE matches, and First Blood awards to preserve grading integrity.
- Instructors can also promote Case Evidences (**Golden Case**) and import/export complete CTF scenarios in **YAML / JSON** from the case CTF panel or REST API. See the [Cases & CTF Mode Guide](Cases-and-CTF-Guide.md) for the full workflow.

---

### Remote Object Storage (Experimental)

Dumps can be uploaded to an S3 compatible bucket (AWS S3, MinIO, ...) instead of the shared `/media` volume:

```ini
USE_S3_STORAGE=True
AWS_STORAGE_BUCKET_NAME=orochi-dumps
AWS_S3_ENDPOINT_URL=https://minio.local:9000   # omit for AWS
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_S3_REGION_NAME=us-east-1
STORAGE_CACHE_MAX_GB=200                       # 0 = never evict
```

- `django-storages[s3]` is **not** installed in the images (boto3 would force `python-dateutil<3` for everybody): add `uv pip install "django-storages[s3]"` to your Django and worker images. `manage.py check` fails with `orochi.E001` when the backend is missing.
- Volatility and the hex viewer need a local file: the first access copies the object into `MEDIA_ROOT/_storage_cache/<dump index>/` (one download per dump, even with several workers), later accesses reuse it. Above `STORAGE_CACHE_MAX_GB` the least recently used dumps are removed from the cache.
- **Limitation**: the ingestion pipeline still unzips and moves dumps inside `MEDIA_ROOT`, so `/media` must stay a shared volume and only the original upload goes through the bucket.

**Azure Blob Storage** works the same way with `USE_AZURE_STORAGE=True` and `AZURE_ACCOUNT_NAME`, `AZURE_ACCOUNT_KEY` (or `AZURE_CONNECTION_STRING`) and `AZURE_CONTAINER` (default `orochi-dumps`). Install `django-storages[azure]` in the Django and worker images; `manage.py check` reports `orochi.E001` when it is missing.

### Sandboxed Workers

Workers parse attacker-controlled memory. `docker-compose.sandbox.yml` hardens them further:

```bash
docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up -d
```

It adds a read-only root filesystem (the named volumes and bounded `tmpfs` mounts stay writable), PID/memory/CPU limits and an **internal-only network**: workers reach the scheduler, PostgreSQL and Redis, nothing else. Docker's default seccomp profile and the base file's `cap_drop: ALL` still apply; uncomment `runtime: runsc` to run them under gVisor. Because workers have no Internet access, automatic symbol downloads (`AUTO_RESOLVE_SYMBOLS`, the 1-click build, `VOLATILITY_REMOTE_ISF_URL`) and ClamAV signature updates stop working: upload symbol files instead, or drop the worker's `networks` override to keep only the filesystem hardening.

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

| Rule ID | Rule Name | Category | Severity | Score | MITRE ATT&CK | Triggers when |
| --- | --- | --- | --- | --- | --- | --- |
| `PROC_INCOHERENT_PARENT_SVCHOST` | Abnormal Parent Process for svchost.exe | Process Tree | Critical | +40 | T1036.005 | `svchost.exe` was not started by `services.exe`. |
| `PROC_INCOHERENT_PARENT_LSASS` | Abnormal Parent Process for lsass.exe | Process Tree | Critical | +45 | T1003.001 | `lsass.exe` was not started by `wininit.exe` (or by `winlogon.exe` on systems without `wininit.exe`, i.e. Windows XP / 2003). |
| `PROC_INCOHERENT_PARENT_SERVICES` | Abnormal Parent Process for services.exe | Process Tree | High | +30 | T1036.005 | Same parent check as lsass.exe, for `services.exe`. |
| `PROC_INCOHERENT_PARENT_SMSS` | Abnormal Parent Process for smss.exe | Process Tree | High | +30 | T1036.005 | `smss.exe` parent is neither System (PID 4) nor `smss.exe`. |
| `PROC_TYPOSQUAT_MASQUERADE` | Typosquatted / Masqueraded Process Name | Masquerading & Path Anomaly | Critical | +45 | T1036.005 | Image name imitates a system binary (e.g. `scvhost.exe`). |
| `PROC_SUSPICIOUS_PATH` | System Critical Binary Executing from User/Temp Path | Masquerading & Path Anomaly | Critical | +40 | T1036.005 | A system binary name runs from a user or temporary folder. |
| `STEALTH_DKOM_UNLINKED` | Hidden Process Unlinked via DKOM | Stealth / DKOM | Critical | +50 | T1014 | A live process found by `psscan` is missing from `pslist`. Exited processes and processes created before the current boot (stale structures of a previous session) are ignored. |
| `CMD_POWERSHELL_OBFUSCATED` | Suspicious Obfuscated PowerShell Execution | Command Line & LOLBins | High | +30 | T1059.001 | PowerShell with encoded / hidden / bypass switches. |
| `CMD_LOLBIN_EXECUTION` | LOLBin Abuse: *binary* | Command Line & LOLBins | High | +30 | per binary | Known living-off-the-land binary used with abusive arguments. |
| `NET_INCONGRUOUS_PROCESS` | Incongruous Network Connection from Non-Network Binary | Network & C2 | Critical | +40 | T1071 | A process that should not talk to the network owns an external connection. |
| `NET_SUSPICIOUS_C2_PORT` | Network Connection on Suspicious C2 Port | Network & C2 | High | +35 | T1071 | Connection to a port commonly used by C2 frameworks. |
| `INJ_MALFIND_EXEC_REGION` | Injected Executable Image (PE / ELF header) | Code Injection | Critical | +40 | T1055 | `malfind` region starting with an `MZ` or ELF header. |
| `INJ_MALFIND_EXEC_REGION` | Executable Private Memory (RWX) | Code Injection | High | +25 | T1055 | `malfind` region that is writable and executable, without executable header. |
| `INJ_MALFIND_EXEC_REGION` | Executable Private Memory | Code Injection | Medium | +10 | T1055 | Other `malfind` executable regions (heaps and shared sections often look like this). |
| `MEM_UNBACKED_EXEC_IMAGE` | Unbacked Executable Image in Writable Memory | Code Injection | Critical | +40 | T1055.001 | `malfind` region starting with an `MZ` header, executable and writable (`PAGE_EXECUTE_READWRITE` / `WRITECOPY`), with no mapped file in `windows.vadinfo.VadInfo` for the same PID and start address (malfind alone when VadInfo was not run). Replaces the `INJ_MALFIND_EXEC_REGION` finding of that region. |
| `LINUX_HOOKED_SYSCALL` | Kernel Rootkit Syscall Table Hook | Linux Threats | Critical | +45 | T1014 | `linux.check_syscall` reports a hooked entry. |
| `LINUX_BASH_ANOMALY` | Suspicious Linux Shell Command | Linux Threats | High | +30 | T1059.004 | Bash history with reverse shells, downloads piped to a shell, etc. |
| `DRIVER_UNEXPECTED_PATH` | Kernel Driver from Unexpected Location | Rootkit / Kernel | High | +30 | T1543.003 | A `windows.modules.Modules` entry has no path, or a path outside the Windows directory (`\SystemRoot\...`, `\??\C:\Windows\...`, `\WINDOWS\system32\...`) or in a writable folder of it (`\Windows\Temp\`). Bare file names (the boot loader's spelling for boot-start drivers such as `ACPI.sys`) and Microsoft Defender's ProgramData driver are accepted. |
| `DRIVER_UNLINKED` | Kernel Driver Hidden from Module List | Rootkit / Kernel | High | +35 | T1014 | A `windows.driverscan.DriverScan` driver object starts outside every module of `windows.modules.Modules` and its name matches none of them. Needs both plugins; driver objects without a start address (built-in pseudo drivers) or without a readable `\Driver\` / `\FileSystem\` name (stale pool-scan hits) are ignored. |

### Cumulative Risk Scoring & Severity Thresholds
When detection rules trigger on a dump, Orochi calculates a cumulative risk score:
$$\text{Risk Score} = \min(100, \sum \text{Finding Weights}, \text{cap of the worst severity})$$

The cap keeps the overall level consistent with the strongest evidence: many Medium findings can reach at most 49 (Medium), many High findings at most 74 (High); only a Critical finding allows 75-100.

The overall dump risk is categorized into five tiers:
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

### Hunting Rules (Sigma-style, no code)

Analysts' own detection logic is added in **Admin › Hunting rules**, without code; a new rule starts from a working example. A rule is YAML evaluated against every row of a dump's successful plugin results, together with the built-in rules, each time triage runs:

```yaml
title: Encoded PowerShell command line
level: high                  # low | medium | high | critical: sets severity and score
logsource:
  plugin: cmdline.CmdLine    # plugin name suffix; omit (or "*") for every plugin
detection:
  encoded:
    Args|contains: [" -enc ", " -encodedcommand "]
  launcher:
    Process|endswith: powershell.exe
  condition: encoded and launcher
```

- Field modifiers: `|contains`, `|startswith`, `|endswith`, `|re` (regular expression), `|all` (every listed value must match; otherwise any). Field names are case-insensitive.
- `condition` combines the named blocks with `and`, `or`, `not` and parentheses; without it every block must match.
- The admin form refuses YAML the engine cannot evaluate. The rule's *Plugin filter* field, when not `*`, overrides `logsource.plugin`; the *Severity*/*Score* fields apply when the YAML has no `level`.
- Each matching row becomes a triage finding named after the rule, so prefer specific conditions.

![Add hunting rule in the admin](images/114_hunting_rule_admin.png)

---

## Dask Monitoring & Task Management

Orochi provides two complementary ways to monitor and control background operations:

### 1. Dask Dashboard
The official **Dask Bokeh Dashboard** is integrated into Orochi for cluster-level diagnostics:
1. Click the **Admin** icon in the navigation bar.
2. Select **Dask Status** (or navigate to `https://localhost/dask/` via Nginx auth proxy, or `http://localhost:8787` if mapped in `docker-compose.override.yml`).
3. View real-time cluster metrics, worker CPU/memory graphs, and task stream waterfalls.

![Dask dashboard](images/009_dask_status.png)

### 2. Integrated Activity Drawer & Task Queue Management

Administrators and analysts can monitor, filter, and control tasks directly through the slide-over Activity Drawer UI or the unified REST API (`/api/tasks/`):

- **Status Filtering & Live Feed**:
  The Activity Drawer includes quick filter chips (`All`, `Running`, `Queued`, `Completed`, `Failed`) allowing forensic analysts to instantly isolate stuck or erroneous jobs.
- **Cluster Correlation & Inspection (`GET /api/tasks/{task_id}`)**:
  Maps raw Dask scheduler keys to corresponding Django models (`manage_upload`, `unzip`, `run_plugin`, `TaskLog`), returning assigned worker node, runtime duration, dump OS, parameters, and full error tracebacks.
- **Bulk & Individual Cancellation (`POST /api/tasks/{task_id}/kill` & `POST /api/tasks/bulk/kill`)**:
  Cancels underlying Dask futures across workers with `client.cancel(keys, force=True)`, transitions dump/result status cleanly to `Cancelled by user`, and immediately frees worker concurrency slots. Administrators can also trigger "Cancel All" directly from the drawer.
- **Universal Task Retry (`POST /api/tasks/{task_id}/retry`)**:
  Provides one-click task retry for failed `TaskLog` jobs, analysis `Result` executions, or memory `Dump` extractions directly from the drawer interface.
- **Log Pruning (`DELETE /api/tasks/prune`)**:
  Allows administrators to purge completed or cancelled `TaskLog` historical records older than a configurable number of days (or all finished logs) to optimize database storage.
- **Dask Worker Recycling (`POST /api/tasks/workers/restart`)**:
  Gracefully restarts worker child processes to clear memory fragmentation after large memory dump extractions without interrupting the central Dask scheduler.
- **Persistent Dask Client Singleton (`orochi/backends/dask_client.py`)**:
  Orochi uses a centralized, thread-safe Dask Client singleton that manages event-loop concurrency across Django worker processes. This eliminates connection thrashing, avoids client leaks, and prevents nested event-loop deadlocks during asynchronous dump ingestion callbacks (`volatility_dask_elk.py`).
- **Internal Protected Media Streaming (`X-Accel-Redirect`)**:
  Static and uploaded forensic files (memory images, dumped executables, symbol archives) are served securely through Nginx internal location redirects (`/media/` internal location in `compose/local/nginx/conf/default.conf`). Django verifies user permissions, validates file path bounds against the media storage root to prevent directory traversal, and offloads byte streaming directly to Nginx.
- **Transaction-Resilient Task Logging**:
  Background task logs (`TaskLog`) use resilient database transaction retries to avoid lock contention under heavy concurrency and broadcast completion notifications to administrators via WebSockets.

---

## Testing and Quality Assurance

Orochi maintains a comprehensive automated test suite powered by **pytest** and **pytest-django** covering models, API routers, background Dask task interfaces, template rendering, and frontend asset integrity.

### Running the Test Suite

Execute tests inside the running Django container or locally with `uv`:

```bash
# Run all tests via Docker Compose
docker compose exec django_wsgi pytest

# Run with verbose output and duration profiling
docker compose exec django_wsgi pytest -v --durations=10

# Run locally with uv (needs the Postgres container on localhost:5432; no env file required)
uv run pytest

# Include the slow tests on the real Windows sample examples/sorpresa.zip (2 GB once extracted)
OROCHI_SAMPLE_TESTS=1 uv run pytest
```

> The images do not include test tools by default. Build them with `--build-arg INSTALL_DEV=true` to run `pytest` inside the containers.

### Running Specific Test Modules

```bash
# Test security architecture, X-Accel-Redirect, AES-256 secrets, and Dask client singleton
docker compose exec django_wsgi pytest orochi/website/tests/test_security_and_dask_refactoring.py

# Test forensic graph, timeline correlation, case notes, and STIX/PDF report exports
docker compose exec django_wsgi pytest orochi/website/tests/test_graph_and_case_collaboration.py

# Test dual-auth API gateway, personal API tokens, and REST API routers
docker compose exec django_wsgi pytest orochi/api/tests/test_backend_api_and_security.py

# Test website UI views, HTMX dynamic interactions, and template tags
docker compose exec django_wsgi pytest orochi/website/tests/test_frontend_and_htmx_views.py

# Test vendored JS/CSS integrity & CDN signatures
docker compose exec django_wsgi pytest orochi/website/tests/test_vendor_assets.py
```

### Additional CLI Management Commands

Administrators can also run specialized management commands via `docker compose exec django_wsgi python manage.py <command>` (or `uv run python manage.py <command>`):
- **`import_local`**: Import a local memory dump directly from the server filesystem:
  ```bash
  python manage.py import_local --filepath /media/uploads/sample.raw --name "Sample" --os Windows --author admin
  ```
- **`run_dwarf`**: Generate Volatility 3 Linux ISF symbols from an unstripped `vmlinux` ELF and optional `System.map` using `dwarf2json`:
  ```bash
  python manage.py run_dwarf --elf /path/to/vmlinux --system-map /path/to/System.map --async
  ```
- **`seed_report_templates`**: Seed default DOCX and HTML investigation report templates for Cases:
  ```bash
  python manage.py seed_report_templates
  ```

- **`reencrypt_service_keys`**: re-encrypt the service API keys with the current `DJANGO_SECRET_KEY` after a key rotation (see [Symmetric Secrets Encryption](#symmetric-secrets-encryption-aes-256-gcm)).

### Continuous Verification
The `tests` GitHub Actions workflow runs `ruff`, `manage.py check`, the missing migrations check and the whole pytest suite against PostgreSQL on every pull request. Docker images (`push.yml`, `push-dev.yml`) are built and published only if that workflow passes. CodeQL runs separately.

---

## Version Information

- **Application:** Orochi (see the [CHANGELOG](../CHANGELOG.md) for the current release)
- **Frameworks:** Django, Dask, Volatility 3
- **License:** MIT
- **Repository:** [https://github.com/LDO-CERT/orochi](https://github.com/LDO-CERT/orochi)

---

© 2026 LDO-CERT — Administrative Management Manual

