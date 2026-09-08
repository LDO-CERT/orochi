# Orochi Services and MaxMind Configuration Guide

_Version 2.5.0 — 2026_  
_Comprehensive Integration Manual for External Threat Intelligence, Local LLMs, Notifications, and Geolocation Forensics_

---

## Table of Contents

- [Overview & Architecture](#overview--architecture)
- [Managing Services in Orochi](#managing-services-in-orochi)
  - [Service Schema & Global Proxy Configuration](#service-schema--global-proxy-configuration)
- [External Services Configuration](#external-services-configuration)
  - [1. VirusTotal](#1-virustotal)
  - [2. MISP (Malware Information Sharing Platform)](#2-misp-malware-information-sharing-platform)
  - [3. Ollama (Local Large Language Model)](#3-ollama-local-large-language-model)
    - [Docker Compose Profile Activation](#docker-compose-profile-activation)
    - [Managing Models (Add, List, Test, Remove)](#managing-models-add-list-test-remove)
    - [Orochi Admin Configuration](#orochi-admin-configuration)
    - [Forensic Case Executive Summaries](#forensic-case-executive-summaries)
    - [Hardware Acceleration (GPU Passthrough)](#hardware-acceleration-gpu-passthrough)
  - [4. Webhook Notifications](#4-webhook-notifications)
  - [5. Slack Alerts](#5-slack-alerts)
  - [6. Email Notifications](#6-email-notifications)
- [User Notification Preferences](#user-notification-preferences)
- [MaxMind GeoIP & ASN Forensics Configuration](#maxmind-geoip--asn-forensics-configuration)
  - [Overview & Forensic Capabilities](#overview--forensic-capabilities)
  - [Required Database Files](#required-database-files)
  - [Obtaining Databases from MaxMind](#obtaining-databases-from-maxmind)
  - [File Placement & Container Ingestion](#file-placement--container-ingestion)
  - [Zero-Rebuild Volume Mount (Recommended)](#zero-rebuild-volume-mount-recommended)
  - [Automating Updates with geoipupdate](#automating-updates-with-geoipupdate)
  - [Enabling Plugin MaxMind Checks in Admin](#enabling-plugin-maxmind-checks-in-admin)
  - [Verification & Testing](#verification--testing)
- [Troubleshooting & Diagnostics](#troubleshooting--diagnostics)

---

## Overview & Architecture

Orochi provides modular extension points to enrich volatile memory analysis with threat intelligence, automated notifications, local AI reasoning, and IP geolocation:

```mermaid
flowchart TD
  subgraph Orochi Core
    Admin["Django Admin (/admin/website/service/)"]
    Engine["Analysis Engine & Dask Workers"]
    Cases["Case Management Workspace"]
    UI["Web UI & Analysis Tables"]
  end

  subgraph Threat Intelligence
    VT["VirusTotal API v3"]
    MISP["MISP Instance"]
  end

  subgraph Local AI Reasoning
    Ollama["Ollama LLM Engine (:11434)"]
  end

  subgraph Notification Pipelines
    Webhook["External Webhooks / SOAR"]
    Slack["Slack Incoming Webhook"]
    Email["SMTP / Mailpit"]
  end

  subgraph Geolocation & ASN
    MaxMind["MaxMind GeoLite2 (/maxmind/*.mmdb)"]
  end

  Admin -->|Configures| Engine
  Engine -->|Hash Lookup| VT
  UI -->|Export Artifacts| MISP
  Cases -->|Executive Summary| Ollama
  Engine -->|Dump & Task Alerts| Webhook
  Engine -->|Dump & Task Alerts| Slack
  Engine -->|Dump & Task Alerts| Email
  UI -->|IP Geolocation Lookup| MaxMind
```

---

## Managing Services in Orochi

All external services are managed centrally from the **Orochi Admin Interface**:

1. Log into Orochi as a superuser at `https://localhost/admin`.
2. Under **WEBSITE**, click **Services** (`/admin/website/service/`).
3. Click **Add Service** (`/admin/website/service/add/`).

![Admin Services Types](images/075_admin_services_types.png)

### Service Schema & Global Proxy Configuration

Every service record in Orochi consists of four standard fields:

| Field | Type | Description |
| :--- | :--- | :--- |
| **Name** | Dropdown Choice | One of: `VirusTotal`, `MISP`, `Ollama`, `Webhook`, `Slack`, `Email`. Each service type is unique in the database. |
| **Url** | CharField (250) | Endpoint URL, host connection string, or target email address depending on the service. |
| **Key** | CharField (250) | API AuthKey, Bearer token, or Model Name (in the case of Ollama). |
| **Proxy** | JSONField | Optional JSON dictionary configuring HTTP/HTTPS proxy gateways. |

#### Proxy Configuration Syntax

When Orochi operates within an enterprise intranet or air-gapped network requiring an outbound proxy, configure the **Proxy** field as a valid JSON object:

```json
{
  "http": "http://proxy.corp.internal:8080",
  "https": "http://proxy.corp.internal:8080"
}
```

If the proxy requires authentication:

```json
{
  "http": "http://username:password@proxy.corp.internal:8080",
  "https": "http://username:password@proxy.corp.internal:8080"
}
```

> [!TIP]
> Leave the **Proxy** field blank if Orochi connects directly to the Internet or to internal Docker containers (e.g. `http://ollama:11434`).

---

## External Services Configuration

### 1. VirusTotal

The **VirusTotal** integration automatically calculates the SHA-256 checksums of executable files and binary artifacts dumped by Volatility plugins (such as `windows.dumpfiles.DumpFiles`, `windows.malfind.Malfind`, and `windows.procdump.ProcDump`) and queries VirusTotal via the official `vt-py` client.

![admin-services-vt](images/037_admin_services.png)

#### Admin Form Configuration:
- **Name:** Select `VirusTotal`
- **Url:** Optional / informational (can be set to `https://www.virustotal.com/api/v3` or left blank)
- **Key:** Your **VirusTotal API Key** (32 or 64 hex characters)
- **Proxy:** Optional proxy JSON object if outbound access requires routing

#### How It Operates:
1. In the Admin panel (**WEBSITE -> Plugins**), ensure plugins that dump files have the `vt_check` checkbox enabled.
2. When Dask workers finish dumping files to `/media/uploads/<dump_index>/<plugin>/`, Orochi's background task executes `run_vt(filepath)` asynchronously.
3. The file's SHA-256 hash is computed and queried against VirusTotal (`/files/{sha256}`).
4. If found, a cached report `<filepath>.vt.json` is generated containing detection statistics (`positives`, `total`, `scan_date`, `permalink`).
5. The web interface displays colored detection badges on extracted files. Clicking the badge reveals engine detection metrics and links directly to the VirusTotal analysis report.

#### Peculiar Details & Rate Limiting:
> [!WARNING]
> **Public vs. Enterprise API Quotas:**  
> Free public VirusTotal API keys are strictly limited to **4 requests per minute** and **500 requests per day**. If a memory plugin dumps 150 executables simultaneously, the worker will hit API rate limits (`[VT] QuotaExceededError`).  
> - For production environments with high dump volume, use an Enterprise/Private API key.  
> - With a public API key, restrict `vt_check` to targeted plugins (e.g. `windows.malfind` only) rather than broad dumpers like `windows.dumpfiles`.

---

### 2. MISP (Malware Information Sharing Platform)

The **MISP** service allows forensic investigators to export extracted memory dumps, executable binaries, and associated threat metadata directly into an existing MISP threat sharing instance.

#### Admin Form Configuration:
- **Name:** Select `MISP`
- **Url:** Full URL of your MISP instance (e.g., `https://misp.cyber.internal`)
- **Key:** MISP **Automation AuthKey** (generated under *MISP -> Administration -> List Users -> View User -> Auth Key*)
- **Proxy:** Optional proxy JSON object

#### How It Operates:
1. In Orochi's dumped file view, click the **Export to MISP** button (`/export?path=...`).
2. Orochi initializes `PyMISP(url, key, ssl=False, proxies=proxy)`.
3. Orochi automatically creates a new MISP event titled:
   ```
   From orochi: <plugin_name>@<dump_name>
   ```
4. It attaches a `FileObject` containing the actual dumped binary artifact.
5. **Automated Signature Correlation:**
   - If **ClamAV** scanned the dumped file and discovered malware, Orochi automatically attaches an `av-signature` object (`software: clamav`, `signature: <signature_name>`) and references it to the file with an `attributed-to` relationship.
   - If **VirusTotal** analysis exists (`<filepath>.vt.json`), detection counts and permalinks are included in the event notes.

#### Peculiar Details:
> [!NOTE]
> By default, Orochi disables strict TLS certificate verification in `PyMISP` (`ssl=False`) to accommodate private cybersecurity labs and on-premise MISP instances that use internal self-signed CA certificates. Ensure your internal network routing to MISP is secure.

---

### 3. Ollama (Local Large Language Model)

Orochi integrates with **Ollama** to provide private, on-premise AI-driven executive summaries for forensic cases (`Case` model). It summarizes extracted findings, MITRE ATT&CK techniques, and suspicious activity into human-readable forensic reports without transmitting sensitive memory artifacts outside your environment.

#### Docker Compose Profile Activation

Ollama is pre-configured as a container service in `docker-compose.yml` under Docker Compose profile `[ "ollama" ]`:

```yaml
  ollama:
    image: ollama/ollama:latest
    profiles: [ "ollama" ]
    container_name: orochi_ollama
    hostname: ollama
    restart: always
    ports:
      - "11434:11434"
    volumes:
      - ./ollama_data:/root/.ollama
```

Because it uses a profile, `docker-compose up` will **not** start Ollama automatically. You must activate the profile:

```bash
# Start Ollama alongside existing running containers
docker-compose --profile ollama up -d ollama

# Or start the entire Orochi stack including Ollama
docker-compose --profile ollama up -d
```

Verify that the Ollama container is running:
```bash
docker ps --filter "name=orochi_ollama"
```

#### Managing Models (Add, List, Test, Remove)

All Ollama models are stored in the host volume `./ollama_data` (mapped to `/root/.ollama` inside the container), guaranteeing models persist across container rebuilds.

##### 1. Pulling / Adding Models
Download your preferred LLM into the Ollama container:

```bash
# Pull default recommended model (Llama 3 8B)
docker exec -it orochi_ollama ollama pull llama3

# Alternative high-performance models:
docker exec -it orochi_ollama ollama pull mistral
docker exec -it orochi_ollama ollama pull qwen2.5:7b
docker exec -it orochi_ollama ollama pull gemma2:9b

# Lightweight model for CPU-only environments:
docker exec -it orochi_ollama ollama pull llama3.2:1b
```

##### 2. Listing Installed Models
To view all models currently downloaded and available:

```bash
docker exec -it orochi_ollama ollama list
```
*Example output:*
```text
NAME               ID              SIZE      MODIFIED
llama3:latest      365c0bd3c000    4.7 GB    2 hours ago
mistral:latest     2ae6f6dd7a3d    4.1 GB    1 day ago
```

##### 3. Testing Model Execution Interactively
Verify inference directly from the CLI:

```bash
docker exec -it orochi_ollama ollama run llama3 "Summarize the primary purpose of memory forensics in one paragraph."
```

##### 4. Removing / Deleting Models
To free disk space, remove models that are no longer needed:

```bash
docker exec -it orochi_ollama ollama rm mistral
```

#### Orochi Admin Configuration

In the Orochi Admin interface (**WEBSITE -> Services -> Add Service**):

- **Name:** Select `Ollama`
- **Url:** `http://ollama:11434`  
  *(When running within the Docker Compose network, use the service hostname `ollama`. If hosting Ollama on another dedicated machine, provide `http://<ip-or-hostname>:11434`)*
- **Key:** **The Model Name to use** (e.g. `llama3`, `mistral`, `qwen2.5:7b`)  
  *(If left blank, Orochi defaults to `llama3`)*
- **Proxy:** Leave blank (direct container communication)

> [!IMPORTANT]
> **The `Key` field represents the Model Name:**  
> In Orochi's implementation (`views.py:1629`), the `Key` field is mapped directly to the target LLM:
> ```python
> model_name = ollama_service.key or "llama3"
> ```
> If you pulled a different model (e.g., `qwen2.5:7b`), enter `qwen2.5:7b` into the **Key** field!

#### Forensic Case Executive Summaries

Once configured:
1. Open any Case in Orochi (`/case/<id>/`).
2. Navigate to **Generate Report** (`/case/<id>/report/`).
3. Select an executive report template and toggle **Use AI Summary** to `true`.
4. Orochi compiles all logged findings, severity rankings, and MITRE ATT&CK techniques, prompts Ollama via `/api/generate`, and injects the synthesized markdown report into the rendered document.

#### Hardware Acceleration (GPU Passthrough)

To accelerate Ollama with an NVIDIA GPU, edit the `ollama` block in `docker-compose.yml`:

```yaml
  ollama:
    image: ollama/ollama:latest
    profiles: [ "ollama" ]
    container_name: orochi_ollama
    hostname: ollama
    restart: always
    ports:
      - "11434:11434"
    volumes:
      - ./ollama_data:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

---

### 4. Webhook Notifications

The **Webhook** service dispatches outbound HTTP POST requests to third-party endpoints (SOAR platforms like Shuffle or Tines, SIEM ingress, or custom APIs) whenever memory dump processing finishes or background tasks complete.

#### Admin Form Configuration:
- **Name:** Select `Webhook`
- **Url:** Target HTTP/HTTPS endpoint (e.g. `https://soar.corp.internal/webhook/orochi-alerts`)
- **Key:** Optional **Bearer Token**. If populated, Orochi automatically appends the header:  
  `Authorization: Bearer <key>`
- **Proxy:** Optional proxy JSON object

#### Outbound JSON Payload Structure:
```json
{
  "event": "dump",
  "title": "Dump Analysis Complete",
  "message": "Memory dump 'WORKSTATION-01' processing completed successfully.",
  "user": "analyst_alice"
}
```

*Events emitted:* `dump` (dump analysis ready) and `task` (general background maintenance or plugin job).

---

### 5. Slack Alerts

Posts real-time forensic activity notifications directly into a designated Slack channel.

#### Admin Form Configuration:
- **Name:** Select `Slack`
- **Url:** Slack **Incoming Webhook URL**  
  *(e.g., `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`)*
- **Key:** Leave blank (not required)
- **Proxy:** Optional proxy JSON object

#### Slack Message Format:
Orochi formats messages with markdown styling and user attribution:
```text
*Dump Analysis Complete*
Memory dump 'DC01-RAM' finished processing 24 plugins.
_User: admin_
```

---

### 6. Email Notifications

Sends notification emails upon completion of memory dumps and tasks to individual analysts or team mailing lists.

#### Admin Form Configuration:
- **Name:** Select `Email`
- **Url:** Central destination email address (e.g. `soc-alerts@corp.internal`).  
  *(If left blank, Orochi falls back to sending notifications to the individual user's registered account email)*
- **Key:** Leave blank (not required)
- **Proxy:** Leave blank

#### Mail Server Delivery Settings:
Email delivery is handled via Django's SMTP backend. In `.envs/.local/.django`:
- For local testing, all emails are caught by **Mailpit** at `http://localhost:8025`.
- In production, set `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, and `EMAIL_HOST_PASSWORD` to point to your corporate SMTP relay.

---

## User Notification Preferences

Configuring a notification service in Admin enables the platform capability, but individual users control their own alerting channels.

Users configure their preferences at `https://localhost/users/notifications/`:

![User Notification Settings](images/028_admin_users_edit.png)

Available toggles:
- **Enable Notifications:** Master switch.
- **Notify via Email:** Toggle delivery to email address.
- **Notify via Webhook:** Toggle delivery to registered Webhook URL.
- **Notify via Slack:** Toggle delivery to Slack channel.
- **Notify on Dump Completion:** Triggers when a memory dump finishes all Volatility plugins.
- **Notify on Task Completion:** Triggers when individual background tasks finish.

---

## MaxMind GeoIP & ASN Forensics Configuration

### Overview & Forensic Capabilities

When analyzing network memory artifacts (such as active connections, listening sockets, and historical TCP endpoints), resolving external IP addresses to their physical country, city, and Autonomous System Number (ASN) is vital for rapid triage.

Orochi integrates **MaxMind GeoLite2 / GeoIP2** databases natively:
- **Network Plugins:** Automatically decorates IP columns (`LocalAddr`, `ForeignAddr`, `Source Addr`, `Destination Addr`) in plugins like `windows.netscan.NetScan`, `windows.netstat.NetStat`, and `linux.sockstat.Sockstat`.
- **Interactive Map Pin:** Renders an interactive map icon (`<i class="fa-solid fa-map-location"></i>`) beside every external IP address.
- **Click-to-Lookup Modal:** Clicking any IP executes `GET /api/utils/maxmind?ip=<target_ip>` and opens a modal displaying:
  - **ASN Details:** Autonomous System Number and Registered ISP / Organization Name.
  - **Location Details:** Country, Country Code, City, and Postal Code.
  - **Coordinates:** Latitude and Longitude.
- **Temporal Diff:** Enables instant GeoIP resolution while comparing network state across two dumps taken at different times.

```mermaid
sequenceDiagram
  autonumber
  actor Analyst as Forensic Analyst
  participant UI as Orochi Web UI (DataTables)
  participant API as Orochi API (/api/utils/maxmind)
  participant MMDB as MaxMind MMDB Files (/maxmind/*.mmdb)

  Analyst->>UI: Inspects NetScan output (e.g. 198.51.100.24)
  UI-->>Analyst: Displays Map Pin Button [fa-map-location]
  Analyst->>UI: Clicks Map Pin Button
  UI->>API: GET /api/utils/maxmind?ip=198.51.100.24
  API->>MMDB: Queries ASN, City, Country Readers
  MMDB-->>API: Returns GeoIP & Organization JSON
  API-->>UI: HTTP 200 {city, country, asn, ...}
  UI-->>Analyst: Renders Geolocation Information Modal
```

---

### Required Database Files

Orochi looks for three standard MaxMind `.mmdb` binary files inside the `/maxmind` container directory:

1. `GeoLite2-ASN.mmdb` — Autonomous System Numbers and ISP names.
2. `GeoLite2-City.mmdb` — Geographic coordinates, cities, regions, and postal codes.
3. `GeoLite2-Country.mmdb` — ISO country codes and country names.

> [!NOTE]
> If at least one of these files exists in `/maxmind`, Orochi enables the GeoIP enrichment engine. Having all three provides complete ASN and geographic resolution.

---

### Obtaining Databases from MaxMind

Due to MaxMind's licensing terms, database files cannot be redistributed publicly without registration. Follow these steps to obtain the latest databases:

1. **Register an Account:** Create a free account at [MaxMind GeoLite2 Sign Up](https://www.maxmind.com/en/geolite2/signup).
2. **Generate a License Key:** In your MaxMind account portal, go to **Manage License Keys** and generate a new key.
3. **Download Database Archives:**
   - Navigate to [Download Databases](https://www.maxmind.com/en/accounts/current/geoip/downloads).
   - Download the **Gzip / Tar.gz** archives for:
     - `GeoLite2 ASN`
     - `GeoLite2 City`
     - `GeoLite2 Country`
4. **Extract the Files:** Extract the `.tar.gz` archives on your host machine to extract the `.mmdb` files:
   - `GeoLite2-ASN.mmdb`
   - `GeoLite2-City.mmdb`
   - `GeoLite2-Country.mmdb`

---

### File Placement & Container Ingestion

Place the extracted `.mmdb` files into the following directory within the Orochi repository:

```text
orochi/
└── compose/
    └── local/
        └── maxmind/
            ├── GeoLite2-ASN.mmdb
            ├── GeoLite2-City.mmdb
            ├── GeoLite2-Country.mmdb
            └── README.txt
```

#### Build-Time Ingestion (Default)

During `docker-compose build`, both `compose/local/django/Dockerfile` and `compose/local/dask/Dockerfile` execute:

```dockerfile
RUN mkdir -p $local_folder /maxmind
COPY ./compose/local/maxmind /maxmind
```

When you rebuild the containers (`docker-compose build`), the files are packaged into the Docker images.

---

### Zero-Rebuild Volume Mount (Recommended)

To update your MaxMind databases periodically without having to rebuild Docker images, add a read-only volume mount to `docker-compose.yml`:

```yaml
  django_wsgi:
    volumes:
      - media_path:/media
      - symbols_path:/app/.venv/lib/python3.13/site-packages/volatility3/symbols
      - plugin_path:/app/.venv/lib/python3.13/site-packages/volatility3/plugins/custom
      - yara_path:/yara
      - cache_path:/root/.cache/volatility3
      - ./compose/local/maxmind:/maxmind:ro   # <--- Add this line

  django_asgi:
    volumes:
      - media_path:/media
      - symbols_path:/app/.venv/lib/python3.13/site-packages/volatility3/symbols
      - plugin_path:/app/.venv/lib/python3.13/site-packages/volatility3/plugins/custom
      - yara_path:/yara
      - cache_path:/root/.cache/volatility3
      - ./compose/local/maxmind:/maxmind:ro   # <--- Add this line

  worker:
    volumes:
      - media_path:/media
      - symbols_path:/app/.venv/lib/python3.13/site-packages/volatility3/symbols
      - plugin_path:/app/.venv/lib/python3.13/site-packages/volatility3/plugins/custom
      - yara_path:/yara
      - cache_path:/root/.cache/volatility3
      - clamav_path:/var/lib/clamav
      - ./compose/local/maxmind:/maxmind:ro   # <--- Add this line
```

With this mapping in place, simply replace the `.mmdb` files in `compose/local/maxmind/` on the host machine. The new data is instantly recognized by Orochi!

---

### Automating Updates with geoipupdate

To automate recurring weekly updates:

1. Install `geoipupdate` on your Docker host:
   ```bash
   sudo apt install geoipupdate
   ```
2. Configure `/etc/GeoIP.conf`:
   ```ini
   AccountID YOUR_ACCOUNT_ID
   LicenseKey YOUR_LICENSE_KEY
   EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
   DatabaseDirectory /path/to/orochi/compose/local/maxmind
   ```
3. Run an initial test:
   ```bash
   geoipupdate -v
   ```
4. Schedule a weekly cron job (`/etc/cron.weekly/geoipupdate`).

---

### Enabling Plugin MaxMind Checks in Admin

1. Open the Admin dashboard at `https://localhost/admin`.
2. Go to **WEBSITE -> Plugins** (`/admin/website/plugin/`).
3. Filter by network plugins (e.g. `windows.netscan.NetScan`, `windows.netstat.NetStat`).
4. Ensure the **Maxmind check** (`maxmind_check`) checkbox is enabled.

---

### Verification & Testing

#### 1. Verify Files Inside the Running Container
Check that the MMDB files exist and are readable:

```bash
docker-compose exec django_wsgi ls -lh /maxmind
```
*Expected output:*
```text
-rw-r--r-- 1 root root  8.0M Mar  1 10:00 GeoLite2-ASN.mmdb
-rw-r--r-- 1 root root 64.0M Mar  1 10:00 GeoLite2-City.mmdb
-rw-r--r-- 1 root root  6.0M Mar  1 10:00 GeoLite2-Country.mmdb
```

#### 2. Test the REST API Endpoint
Send a test query to the MaxMind API router:

```bash
curl -k -u admin:admin "https://localhost/api/utils/maxmind?ip=8.8.8.8"
```
*Expected response (HTTP 200):*
```json
{
  "autonomous_system_number": 15169,
  "autonomous_system_organization": "GOOGLE",
  "country": {
    "iso_code": "US",
    "name": "United States"
  },
  "city": {
    "name": null
  },
  "location": {
    "latitude": 37.751,
    "longitude": -97.822
  }
}
```

#### 3. Inspect the UI
Open any memory dump analysis containing network connections (e.g. `windows.netscan`). Each IP in `ForeignAddr` will feature a map pin button. Click the button to see the geolocation modal in action.

---

## Troubleshooting & Diagnostics

| Symptom | Probable Cause | Resolution |
| :--- | :--- | :--- |
| **MaxMind map pin icon missing in analysis tables** | Missing `.mmdb` files or plugin column not matched. | Verify files exist in container (`docker-compose exec django_wsgi ls /maxmind`). Ensure the plugin outputs `ForeignAddr`, `LocalAddr`, `Source Addr`, or `Destination Addr`. |
| **Ollama connection refused (`Failed to connect to ollama:11434`)** | Ollama container not started or profile not specified. | Start with profile: `docker-compose --profile ollama up -d ollama`. Check status with `docker ps`. |
| **Ollama returns `model 'llama3' not found`** | The specified model has not been pulled. | Run `docker exec -it orochi_ollama ollama pull llama3`. If using a different model, update the **Key** field in Admin to match. |
| **VirusTotal rate limit exceeded (`QuotaExceededError`)** | Public VT API key hit 4 req/min limit. | Use a private VT API key, or disable `vt_check` on plugins that dump large quantities of files. |
| **MISP export fails with connection/SSL error** | Invalid MISP URL, key, or network routing failure. | Test connectivity from container: `docker-compose exec django_wsgi curl -k <misp_url>`. Verify AuthKey in Admin. |
| **Slack / Webhook alerts not delivered** | User notification toggles disabled. | Navigate to `https://localhost/users/notifications/` and ensure both **Enable Notifications** and the respective channel are toggled on. |

---

© 2026 LDO-CERT — Collaborative Memory Forensics Platform
