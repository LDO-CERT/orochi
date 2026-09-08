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
  - [User Plugins](#user-plugins)
- [Updating and Maintenance](#updating-and-maintenance)
  - [Update Plugins](#update-plugins)
  - [Update Symbols](#update-symbols)
  - [Add Custom Plugins](#add-custom-plugins)
  - [Update Vendored Libraries](#update-vendored-libraries)
- [YARA Rules Management](#yara-rules-management)
  - [Update Rules](#update-rules)
  - [Generate Default Rule](#generate-default-rule)
  - [Manage Rules](#manage-rules)
  - [Manage Rulesets](#manage-rulesets)
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

Enable and configure optional integrations.

- **VirusTotal:** Queries hashes (SHA-256) of dumped files automatically.  
  If a plugin generates 100 files, 100 VirusTotal queries will be performed automatically.
- **MISP:** Allows users to export findings directly to a configured MISP instance (API key and URL required).

![admin-services](images/037_admin_services.png)
![admin-services](images/038_admin_services_add.png)

### User Plugins

Admins can manage which plugins run automatically for specific users.  
For example, enabling **Timeliner** for user2 ensures it runs by default on all of their dumps.

![admin-plugins](images/039_admin_plugins.png)
![admin-plugins-edit](images/040_admin_plugins_edit.png)

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

