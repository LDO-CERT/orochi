# Orochi Admin Guide

_Version 2.4.1 — October 2025_  
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
- [YARA Rules Management](#yara-rules-management)
  - [Update Rules](#update-rules)
  - [Generate Default Rule](#generate-default-rule)
  - [Manage Rules](#manage-rules)
  - [Manage Rulesets](#manage-rulesets)
- [Dask Monitoring](#dask-monitoring)
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

Displays files created by Volatility plugins that use the **dump flag**.  
Administrators can delete files as needed.

![admin-dumps-extracted](images/031_admin_dumps_extracted.png)
![admin-dumps-extracted-edit](images/032_admin_dumps_extracted_edit.png)

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

## Dask Monitoring

The **Dask Status Dashboard** is integrated into Orochi for real-time worker and task monitoring.

1. Click the **Admin** icon in the navigation bar.
2. Select **Dask Status**.
3. The Dask Bokeh dashboard opens, displaying worker activity, task progress, and resource utilization.

![dask-monitoring](images/0068_dask_monitoring.png)

---

## Version Information

- **Application:** Orochi v2.4.1
- **Frameworks:** Django, Dask, Volatility 3
- **License:** MIT
- **Repository:** [https://github.com/LDO-CERT/orochi](https://github.com/LDO-CERT/orochi)

---

© 2025 LDO-CERT — Administrative Management Manual
