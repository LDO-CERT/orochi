## Changelog
<details open>
  <summary><b>OROCHI 2.8.2</b></summary>

  ### New Features

  #### Cases & investigation
  * **Case Bundle export & import** [[#1539](https://github.com/LDO-CERT/orochi/issues/1539)]: move a whole case to another Orochi as a `.orochi.zip` (evidence, findings, notes, timeline, plugin results and extracted files, with a SHA-256 manifest). **Export** on the case page, **Import** in the sidebar; edited bundles are refused.
  * **Investigation timeline** [[#1538](https://github.com/LDO-CERT/orochi/issues/1538)]: add manual events to a case; forensic artefact times and manual events are shown apart from analyst activity.
  * **Complete case reports** [[#1540](https://github.com/LDO-CERT/orochi/issues/1540)]: Markdown, HTML and PDF reports now include scope (dump hashes, OS), IOCs, the forensic timeline and a technical appendix (plugins, parameters, Volatility version).
  * **Threaded row annotations** [[#1669](https://github.com/LDO-CERT/orochi/issues/1669)]: reply to a note on a plugin row.
  * **MITRE ATT&CK for ICS** [[#1667](https://github.com/LDO-CERT/orochi/issues/1667)]: ICS techniques (`T08xx`) and an `ics-attack` Navigator layer.
  * **Recycle bin**: deleting a dump moves it to the recycle bin for `DUMP_RETENTION_DAYS` days (default 7) with **Restore** and **Delete permanently**.

  #### CTF mode [[#1542](https://github.com/LDO-CERT/orochi/issues/1542)]
  * Publish a challenge: every participant gets a private case and the challenge dumps (**CTF** in the top bar).
  * Hints with a point cost, a full-page live scoreboard with the solve timeline, ATT&CK progress in the CTF panel.

  #### Analysis
  * **Forensic integrity** [[#1674](https://github.com/LDO-CERT/orochi/issues/1674)]: every plugin run records who ran it, when, Volatility/plugin versions, symbols and parameters; rows replaced by a re-run are kept and listed in **History**; uploads are hashed as received and **Verify Integrity** re-hashes on demand.
  * **Full-result export** [[#1559](https://github.com/LDO-CERT/orochi/issues/1559)]: CSV, JSON, Excel and XML export all the rows of a plugin, not only the visible page.
  * **Playbooks** [[#1544](https://github.com/LDO-CERT/orochi/issues/1544)]: custom playbooks are versioned, a personal **Auto-run** runs a playbook on your new uploads, and the dump's Playbooks page shows the status of each plugin.
  * **Hunting rules** [[#1545](https://github.com/LDO-CERT/orochi/issues/1545)]: Sigma-style YAML rules (*Admin › Hunting rules*) evaluated by triage.
  * **Automatic Linux symbols** [[#167](https://github.com/LDO-CERT/orochi/issues/167)]: Linux debug symbols are resolved automatically; the **Symbol Assistant** explains missing or wrong symbols, builds an ISF from an uploaded `vmlinux` and offers **Retry Unsatisfied Plugins** [[#1553](https://github.com/LDO-CERT/orochi/issues/1553), [#1554](https://github.com/LDO-CERT/orochi/issues/1554)].
  * **Cortex analyzers** [[#1550](https://github.com/LDO-CERT/orochi/issues/1550)]: run a Cortex analyzer on an extracted file from the **Cortex** button of a case evidence.

  #### Automation
  * **Python client & CLI (`orochi-client`)** [[#1574](https://github.com/LDO-CERT/orochi/issues/1574)]: upload, launch playbooks, follow progress and export reports or bundles from scripts (`clients/python/`).
  * **Unified notifications** [[#167](https://github.com/LDO-CERT/orochi/issues/167), [#1671](https://github.com/LDO-CERT/orochi/issues/1671)]: in-app toasts; new High/Critical triage and case findings are sent to the users who can see the dump, by e-mail, webhook or Slack according to their preferences.

  ### Improvements & Fixes
  * **More accurate triage** [[#1662](https://github.com/LDO-CERT/orochi/issues/1662), [#1543](https://github.com/LDO-CERT/orochi/issues/1543)]: fewer false positives (Linux zombie tasks and threads, Windows XP parents, processes re-listed during a re-run); new signals for kernel drivers loaded from unexpected paths or hidden from the module list, unbacked executable images, DLLs from user-writable folders, YARA and ClamAV hits.
  * **Timeliner** [[#1556](https://github.com/LDO-CERT/orochi/issues/1556), [#1666](https://github.com/LDO-CERT/orochi/issues/1666)]: the stored timeline now matches the Volatility CLI row for row.
  * **Threat-intel enrichment** [[#1548](https://github.com/LDO-CERT/orochi/issues/1548)]: unknown indicators are shown as *not found* instead of errors; *Enrich all* reports found / unknown / failed.
  * **STIX 2.1 export** [[#1549](https://github.com/LDO-CERT/orochi/issues/1549)]: strictly valid bundles (IPv6, escaped patterns, YARA matches as notes).
  * **Tasks** [[#1564](https://github.com/LDO-CERT/orochi/issues/1564), [#1663](https://github.com/LDO-CERT/orochi/issues/1663)]: retry and restart really re-run the plugin and report what they scheduled; dumps no longer stay *Processing* or *Unzipping* forever; a cancelled YARA feed sync stops.
  * **Plugin parameters** (e.g. `pid`, `dump`) are no longer lost on dumps with a cached Volatility configuration.
  * **Network view** [[#1557](https://github.com/LDO-CERT/orochi/issues/1557)] shows DNS records and tells when GeoIP data is missing.
  * **AI narrative** [[#1668](https://github.com/LDO-CERT/orochi/issues/1668)]: uses local LLM endpoints only (unless allowed) and never states PIDs, offsets or hashes outside its citations.
  * **Roles**: Reviewers and ReadOnly users no longer see buttons they cannot use (upload, edit, delete, add to case).
  * **Cases**: adding evidence or promoting a finding to a case shared with several collaborators no longer fails; manual timeline events are no longer listed twice.
  * **Messages**: confirmations (sign-in, timeline, …) appear on the page you land on.
  * **Responsiveness**: the site no longer slows down when the Dask scheduler is unreachable.
  * **Password reset by API** works again (`POST /api/auth/request_password_reset`).
  * **Security**: the VirusTotal report endpoint could read files outside the dump folder; the Cortex endpoint no longer accepts a caller-supplied URL; bundle import cannot link dumps the importer cannot see; CSV exports neutralize formula cells; secrets with control characters are cleaned before storage [[#1567](https://github.com/LDO-CERT/orochi/issues/1567)].
  * **API**: consistent errors (`401` not signed in, `403` not allowed, `404` not found, `400` failed), no more `500` on several endpoints, dump status and per-plugin progress in the responses [[#1661](https://github.com/LDO-CERT/orochi/issues/1661)].

  ### For Administrators
  * **Offline start** [[#1670](https://github.com/LDO-CERT/orochi/issues/1670)]: the web container starts without Internet access (`TAILWIND_REBUILD=0` by default).
  * **Safer PostgreSQL upgrade** [[#1575](https://github.com/LDO-CERT/orochi/issues/1575)] with a verified snapshot; build the `value_result_idx` index online before `migrate` on large databases [[#1673](https://github.com/LDO-CERT/orochi/issues/1673)].
  * **Sandboxed workers** [[#1570](https://github.com/LDO-CERT/orochi/issues/1570)]: optional `docker-compose.sandbox.yml` (read-only filesystem, resource limits, no Internet, optional gVisor).
  * **Azure Blob storage** [[#1562](https://github.com/LDO-CERT/orochi/issues/1562)] for dumps with `USE_AZURE_STORAGE`.
  * **Settings** [[#256](https://github.com/LDO-CERT/orochi/issues/256), [#1576](https://github.com/LDO-CERT/orochi/issues/1576)]: separate production and development settings, runtime settings in *Admin › Extra settings*.
  * **Web workers**: `GUNICORN_WORKERS` (default 2) and `GUNICORN_THREADS` (default 4).
  * New cron commands: `manage.py purge_recycle_bin` and `manage.py yara_feeds_update`.
  * Signed release images with SBOM and provenance [[#1672](https://github.com/LDO-CERT/orochi/issues/1672)].

  ### Docs
  * Guides updated for all the features above, with a role table, API error codes and refreshed screenshots.
</details>

<details>
  <summary><b>OROCHI 2.8.1</b></summary>

  * **Security**: extracted-file views (`vt`, `json_view`, `download`, MISP export) now only serve files inside a dump folder under `MEDIA_ROOT` that the user can see; fixes reading arbitrary files and an inverted permission check in `json_view`.
  * **Security**: escaped user and memory-dump values in error responses, the Network Hub drawer and the entity picker (XSS); export errors no longer return raw exception text.
  * **Dependencies**: tornado 6.6.1 (Dependabot alerts), Django 6.1.3, django-allauth 65.22.1, django-ninja 1.8.0, yara-x 1.24.0 and other patch/minor updates; marked 18.3.0 and sweetalert2 11.26.26.
</details>

<details>
  <summary><b>OROCHI 2.8.0</b></summary>

  * **Security**: `DJANGO_SECRET_KEY` is now mandatory (no default key), with `DJANGO_SECRET_KEY_FALLBACKS` and the `reencrypt_service_keys` command for rotation; internal services (Postgres, Redis, Dask scheduler, Ollama, Mailpit) are no longer published on all interfaces; self-registration is closed unless `DJANGO_ACCOUNT_ALLOW_REGISTRATION=True` (the setting was previously ignored); per-service TLS verification (`Service.verify_ssl`); fixed access control on plugin restart and evidence creation; zip-slip protection for custom plugins.
  * **CTF mode** [[#1542](https://github.com/LDO-CERT/orochi/issues/1542)]: CTF Challenge panel in the case page (students answer and unlock hints, instructors manage questions, live leaderboard), hashed answers, hints with point cost, brute force throttling, REST API and admin pages.
  * **Integrations**: SIEM forwarding (Splunk HEC / Elastic / Sentinel) [[#1568](https://github.com/LDO-CERT/orochi/issues/1568)], TheHive 5 case export [[#1550](https://github.com/LDO-CERT/orochi/issues/1550)] with case page buttons, CAPE / Cuckoo submission of extracted files from plugin rows and case evidences [[#1551](https://github.com/LDO-CERT/orochi/issues/1551)].
  * Sign-up link hidden from the login page when registration is closed.
  * **Experimental S3 / MinIO dump storage** with local LRU cache [[#1562](https://github.com/LDO-CERT/orochi/issues/1562)].
  * **Linux AArch64** support patch re-based on current volatility3 (`77ff0b1932d7`, restoring the VMCOREINFO stacker and Linux-specific Intel layers lost in 2.7.0 images), with 52-bit VA translation fixes (`_ttb_bitsize >= 52`, `ID_AA64MMFR1_EL1` pre-init) and recursive enablement of all 59 Linux plugins (`constants/architectures.py` + `plugins/linux/**`); build fails if volatility3 changes under the patch.
  * **Process 360° Dossier (`/dump/<index>/process/<pid>/dossier`)**: cross-plugin process investigation modal & standalone page accessible by clicking any `PID`/`PPID` pill in DataTables or the **Dossier** button in the Interactive Process Tree Inspector; aggregates process ancestry, child processes, command lines, triage alerts, extracted secrets, `malfind` injections, console buffers, network sockets, environment variables, modules/memory maps, privileges/SIDs/capabilities, and open handles, with a **Forensic Plugin Coverage Bar** and 1-click **Run Missing Plugins** Dask launcher.
  * **Single-Plugin Forensic Triage Ribbons & DataTable Upgrades**: interactive summary ribbons for `windows.svcscan.SvcScan` (running/stopped/drivers/suspicious binary paths), `windows.ldrmodules.LdrModules` (unlinked PEB modules audit + `"Unlinked Only"` filter pill), `windows.vadinfo.VadInfo` / `linux.proc.Maps` / `mac.proc_maps.Maps` (`RWX` and anonymous/memfd executable regions), `windows.sessions.Sessions` (per-user logon filter pills), extended Console/Terminal replay (`windows.consoles.Consoles`, `windows.cmdscan.CmdScan`, `psaux`), automatic `0x...` hex formatting for memory offsets/addresses, single-dump `orochi_*` column decluttering, and `django-easyaudit` bulk-delete optimization.
  * **YARA Forensic Toolkit**: added **YARA Live Tester & Retro-Hunt Sandbox** in `/users/rules/` (`POST /api/rules/test` & `POST /api/rules/scan_file`) supporting instant `yara-x` hunting across indexed DB forensic artifacts, extracted dump files (`dumped_files` with `.yara.json` sidecars), ad-hoc text buffers, and uploaded samples; **YARA Forensic Match Intelligence & MITRE ATT&CK Correlation Ribbon** for `YaraScan`/`VadYaraScan`/`VmaYaraScan`; and 1-click **Generate YARA** rule builder on `malfind` injected memory cards (`POST /api/rules/generate`).
  * Plugin re-run with file parameters through API and UI [[#1573](https://github.com/LDO-CERT/orochi/issues/1573)], plus revamped **Community Plugins Catalog (`orochi_plugins`) & Custom Plugin Installer** (`GET /api/plugins/catalog` with separate searchable **Description** and **Last Update** columns parsed from upstream `data.json`, direct `.zip` upload in `/users/plugins/`, multi-plugin `.zip` discovery, Python 3.15 `uv pip` dependency installer, and Dask worker payload distribution).
  * **CI & Docker**: tests, lint and migration checks on every pull request; images are published only when they pass; Buildx scoped GHA cache and workflow concurrency; Docker Swarm healthchecks on `postgres` and `redis`; fast Django startup flags (`TAILWIND_REBUILD`, `TAILWIND_WATCH`, `COLLECTSTATIC_ON_START`). `uv run pytest` works without env files.
  * **Linux BTF ISF Builder (`btf2json`)**: integrated Valentin Obst's [`btf2json`](https://github.com/vobst/btf2json) compiled from source via multi-stage Rust builds in Django and Dask Docker images, with automatic Volatility 3 ISF schema patching (`btf`/`symdb`) in `compose/local/vol_fix/apply.sh`, `Downloader.process_btf_kernel`, `generate_btf_isf_task` Dask worker task, `POST /api/symbols/btf_generate` API endpoint, `manage.py run_btf` command, **Build BTF ISF (btf2json)** modal in `/list_symbols`, and banner pre-filled BTF builder inside the Linux Smart Symbol Assistant.
  * **Hardening & Refactoring**: `role_required` HTTP 403 enforcement (avoiding login redirect loops for authenticated users), dual-auth (`django_auth` + Bearer token) consistency across API routers, modularized `orochi/website/views/` package, UI accessibility & theme-toggle fixes, and comprehensive documentation updates including a dedicated [Cases & CTF Mode Guide](docs/Cases-and-CTF-Guide.md).
</details>

<details>
  <summary><b>OROCHI 2.7.0</b></summary>

  * **Case Collaboration & Live Presence**: Added real-time analyst presence indicators and shared collaborative notes within investigation cases.
  * **Multi-Host Forensic Graph & Timeline**: Correlate processes, network sockets, and memory injections across multiple dumps in a unified relational graph and chronological timeline.
  * **Multi-Format Case Reports**: Export investigation cases directly to publication-ready PDF, technical Markdown, standalone HTML, and OASIS STIX 2.1 threat intelligence bundles.
  * **Personal API Tokens**: Added Bearer token authentication (`Authorization: Bearer oro_...`) and token management endpoints for headless automation and scripts.
  * **Credential & Download Security**: Encrypted external service API keys at rest with AES-256 and secured dump/artifact downloads against path traversal via internal streaming.
  * **Faster Database Ingestion**: Optimized bulk processing for large memory dumps to significantly speed up indexing and avoid timeouts.
  * **Improved Task Stability**: Centralized background compute connections to eliminate freezes and deadlocks during concurrent dump analysis.
  * **Tailwind CSS 4 Modernization**: Migrated frontend styling to native Tailwind CSS 4 engine with CSS-first configuration and upgraded `django-tailwind-cli`.
  * **Expanded Test Suite**: Added 30 automated tests covering security, concurrency, collaboration, and API endpoints.
</details>

<details>
  <summary><b>OROCHI 2.6.0</b></summary>

  * Fix MISP export regression [[#1547](https://github.com/LDO-CERT/orochi/issues/1547)]
  * Add automated per-dump IOC Extraction Hub extracting public foreign IPs, dumped-file hashes (SHA256, MD5), YARA hits, and web indicators (URLs, domains) [[#1548](https://github.com/LDO-CERT/orochi/issues/1548)]
  * Add multi-source Threat Intelligence enrichment supporting VirusTotal, AbuseIPDB, AlienVault OTX, and GreyNoise with composite threat scoring (0-100)
  * Add 1-click Export to MISP (bulk or selected indicators with IDS flags) and 1-click Promote finding to Case
  * Add multi-format indicator download supporting STIX 2.1 JSON bundle, CSV spreadsheet, and JSON report
  * Add external service connection test utility for administrators in `/service/test-connection`
  * Add Interactive Process-Tree Visualizer with infection chain tracing, zoom/pan canvas, search, and process inspector drawer [[#1555](https://github.com/LDO-CERT/orochi/issues/1555)]
  * Add dedicated REST API endpoint `GET /api/dumps/{index}/process-tree` returning hierarchical process node structures enriched with triage findings, cmdlines, and memory secrets
  * Integrate Process Tree and IOC Hub into Dump Analysis tabs, Dump Card action menus, and Behavioral Triage views
  * Add Smart Symbol Assistant with automated Linux banner extraction, ISF lookup, and kernel banner matching [[#1553](https://github.com/LDO-CERT/orochi/issues/1553)]
  * Add automated PE Symbol Lookup and symbol generation for Windows kernel binaries (`ntoskrnl.exe`, `ntkrnlmp.exe`) [[#1310](https://github.com/LDO-CERT/orochi/issues/1310)]
  * Add PostgreSQL database version upgrade management guide and automated upgrade tooling [H5]
  * Add API Plugin File Parity with direct zip package upload, source inspection, export, worker deletion, and sync [[#1573](https://github.com/LDO-CERT/orochi/issues/1573)]
  * Add Task Queue Management with dedicated `/api/tasks/` router, status filters, bulk cancellation, universal retry, log pruning, and worker process recycling [[#1564](https://github.com/LDO-CERT/orochi/issues/1564)]
  * Enhance Activity Drawer UI with status filter chips (All, Running, Queued, Completed, Failed), Cancel All, Prune Logs, Restart Workers, and per-task retry buttons
  * Add Network Connection Graph & Geo-Map Visualizer with force-directed topology graph, dark-tile world map with MaxMind GeoIP resolution, socket table, inspector drawer, CSV export, and REST API `GET /api/dumps/{index}/network` [[#1557](https://github.com/LDO-CERT/orochi/issues/1557)]
  * Add Linux/ARM ISF dwarf2json Helper & Worker Dwarf Task with raw kernel ELF/System.map parsing, `run_dwarf` management command, `generate_dwarf_isf_task` Dask worker task, and `POST /api/symbols/dwarf_generate` [[#1554](https://github.com/LDO-CERT/orochi/issues/1554) / [#272](https://github.com/LDO-CERT/orochi/issues/272)]
  * Add Automated YARA Rule Feed Updater & Worker Synchronization with feed tracking fields (`last_sync`, `last_sync_status`, `auto_update`), default rule recompilation helper, Dask worker verification, and `/api/rules/feeds/` endpoints [[#1552](https://github.com/LDO-CERT/orochi/issues/1552) / [#272](https://github.com/LDO-CERT/orochi/issues/272)]
  * Add Incident Response Auto-Triage Playbooks engine with 6 predefined threat recipes (Quick Malware, Ransomware Hunt, Stealth Rootkit, Linux Triage, Linux Rootkit, Mac Triage), chained plugin worker execution, automated triage scoring trigger, HTMX modal, and `/api/playbooks/` router [[#1544](https://github.com/LDO-CERT/orochi/issues/1544)]
</details>

<details>
  <summary><b>OROCHI 2.5.0</b></summary>

  * Add Investigation Workspace with Cases, Evidence, Findings, Timeline, CTF mode, and report generation [[#1534](https://github.com/LDO-CERT/orochi/issues/1534)]
  * Add MITRE ATT&CK technique tagging, interactive Coverage Matrix heatmap, and Navigator layer export [[#1541](https://github.com/LDO-CERT/orochi/issues/1541)]
  * Add Temporal Diff analysis and Host entity for chronological T1 vs T2 delta forensics
  * Add Cross-Dump Global Search powered by PostgreSQL full-text search with "Add to Case" triage
  * Add real-time Tasks & Activity slide-over drawer with Dask monitoring and one-click task re-run
  * Add Web Symbols Management Hub (`/list_symbols`) for ISF symbol inspection and package upload
  * Add interactive forensic JSON viewer (`vanilla-jsoneditor`) with dark/light mode and tree navigation
  * Add real-time WebSocket notifications for admins [[#1566](https://github.com/LDO-CERT/orochi/issues/1566)] and user alerts (Email, Webhook, Slack)
  * Improve YARA synchronization with incremental block compilation and PostgreSQL sanitization
  * Integrate `django-easy-audit` for database and authentication audit logging [[#1563](https://github.com/LDO-CERT/orochi/issues/1563)]
  * Add DataTables export functionalities (CSV, Excel, JSON, XML) and host/folder autocomplete
  * Update frontend libraries and add offline asset vendor manager (`update_vendor_js`)
</details>

<details>
  <summary><b>OROCHI 2.4.2</b></summary>

  * Run management task on workers [[#272](https://github.com/LDO-CERT/orochi/issues/272)]
  * Add update cache task at startup
  * Complete migration from Bootstrap to Tailwind CSS, featuring fully responsive UI components.
  * Native Dark/Light mode theme toggling.
  * Replaced heavy jQuery/Bootstrap DOM updates with HTMX for dynamic partial page rendering.
  * Replaced Bootbox/Bootstrap modules with modern Tailwind-compatible alternatives (SweetAlert2, Flowbite).
</details>

<details>
  <summary><b>OROCHI 2.4.1</b></summary>

  * Misp configuration is not working [[#1359](https://github.com/LDO-CERT/orochi/issues/1359)]

</details>

<details>
  <summary><b>OROCHI 2.4.0</b></summary>

  * Update js libs (coloris, bootstrap toast)
  * Replace drf with django-ninja [[#1073](https://github.com/LDO-CERT/orochi/issues/1073)]
  * Management task on workers [[#272](https://github.com/LDO-CERT/orochi/issues/272)]
  * dask Dashboard Diagnostics authenticated [[#1308](https://github.com/LDO-CERT/orochi/issues/1308)]

</details>

<details>
  <summary><b>OROCHI 2.3.0</b></summary>

  * Removed elasticsearch
  * Add clamav volume to keep antivirus updated
  * Recompile rules via admin command
  * Add experimental support for ARM64
  * Manage BodyFile file in timeliner plugin
  * export/import [[#1102](https://github.com/LDO-CERT/orochi/issues/1102)]
  * signal for dump/result changes are very verbose [[#1074](https://github.com/LDO-CERT/orochi/issues/1074)]
  * replace drf & co. with django-ninja [[#1073](https://github.com/LDO-CERT/orochi/issues/1073)]
  * Add Two-Factor Authentication [[#1099](https://github.com/LDO-CERT/orochi/issues/1099)]
  * Admin: Assign multiple dumps to user [[#1082](https://github.com/LDO-CERT/orochi/issues/1082)]
  * Multi-arch build and images [[#1098](https://github.com/LDO-CERT/orochi/issues/1098)]
  * Custom logo in the login page [[#1083](https://github.com/LDO-CERT/orochi/issues/1083)]
</details>

<details>
  <summary><b>OROCHI 2.2.0 [2024/03/26]</b></summary>

  * Upload ntoskrnl.exe and generate symbol [[#1020](https://github.com/LDO-CERT/orochi/issues/1020)]
  * evaluate possibility to switch from daphne to uvicorn for asgi [[#982](https://github.com/LDO-CERT/orochi/issues/982)]
  * Improve path flexibility for local import [[#451](https://github.com/LDO-CERT/orochi/issues/451)]
  * uv for installing requirements [[#1030](https://github.com/LDO-CERT/orochi/issues/1030)]
  * Read only users for educational. [[#947](https://github.com/LDO-CERT/orochi/issues/947)]
  * Add use case example with API. [[#248](https://github.com/LDO-CERT/orochi/issues/248)]
  * put custom plugins under volatility3 /plugins/ [[#1068](https://github.com/LDO-CERT/orochi/issues/1068)]
  * Improve tree rendered plugins
  * Execute Regipy plugins on windows images
</details>

<details>
  <summary><b>OROCHI 2.1.1 [2024/02/13]</b></summary>

  * ADD more info on foreign addr in netstat [[#494](https://github.com/LDO-CERT/orochi/issues/494)]
  * Expand/Collapse folders [[#1006](https://github.com/LDO-CERT/orochi/issues/1006)]
</details>

<details>
  <summary><b>OROCHI 2.1.0 [2024/02/12]</b></summary>

  * add possibility to download all symbols from a given ISF URL [[#1007](https://github.com/LDO-CERT/orochi/issues/1007)]
  * organize memory dumps in folders [[#1006](https://github.com/LDO-CERT/orochi/issues/1006)]
  * show plugins description with mouse over text [[#1000](https://github.com/LDO-CERT/orochi/issues/1000)]
  * Add comment to dump [[#988](https://github.com/LDO-CERT/orochi/issues/988)]
  * Add download button for uploaded dumps [[#983](https://github.com/LDO-CERT/orochi/issues/984)]
  * Store exctracted dump info in elastic [[#983](https://github.com/LDO-CERT/orochi/issues/983)]
  * sort & filter on uploaded dumps [[#968](https://github.com/LDO-CERT/orochi/issues/968)]
  * Run plugin on multiple images [[#951](https://github.com/LDO-CERT/orochi/issues/951)]
  * Ldap support [[#948](https://github.com/LDO-CERT/orochi/issues/948)]
  * Symbols management [[#918](https://github.com/LDO-CERT/orochi/issues/918)]
  * Custom Symbol Table Files [[#695](https://github.com/LDO-CERT/orochi/issues/695)]
  * BUG: if docker fails while plugin is running it'll remain running forever [[#81](https://github.com/LDO-CERT/orochi/issues/81)]
</details>

<details>
  <summary><b>OROCHI 2.0.1 [2024/01/18]</b></summary>

  * Add tree visualization for other plugin
  * Add support for linux dump
  * Paginate analysis results in table  [[#975](https://github.com/LDO-CERT/orochi/issues/975)]
  * error passing CSRF_TRUSTED_ORIGINS  [[#976](https://github.com/LDO-CERT/orochi/issues/976)]
</details>

<details>
  <summary><b>OROCHI 2.0.0 [2024/01/09]</b></summary>

  * Update libs and UI
  * Re-Run default enabled plugins [[#950](https://github.com/LDO-CERT/orochi/issues/950)]
  * Pending task count [[#255](https://github.com/LDO-CERT/orochi/issues/255)]
  * Update vt python libs
</details>

<details>
  <summary><b>OROCHI 1.3.1 [2022/01/17]</b></summary>

  * Unzip password protected file [#484](https://github.com/LDO-CERT/orochi/issues/484)
  * Md5 support for dumped files [#489](https://github.com/LDO-CERT/orochi/issues/489)
  * Improve elasticsearch details [#462](https://github.com/LDO-CERT/orochi/issues/462)
  * Add info for uploaded dumps [#488](https://github.com/LDO-CERT/orochi/issues/488)
  * HEX viewer [#495](https://github.com/LDO-CERT/orochi/issues/495)
</details>

<details>
  <summary><b>OROCHI 1.3.0 [2021/10/02]</b></summary>

  * Manage custom plugins [#245](https://github.com/LDO-CERT/orochi/issues/245)
  * YARA rules management [#28](https://github.com/LDO-CERT/orochi/issues/28)
  * Manage results with more than 10k rows [#3](https://github.com/LDO-CERT/orochi/issues/3)
  * Added docker-compose for swarm [#252](https://github.com/LDO-CERT/orochi/issues/252) with documentation [#257](https://github.com/LDO-CERT/orochi/issues/257)
  * Improved search [#271](https://github.com/LDO-CERT/orochi/issues/271)
  * Use multi-stage builds [#242](https://github.com/LDO-CERT/orochi/issues/242)
  * Pre built images available on [ghcr](https://github.com/orgs/LDO-CERT/packages?repo_name=orochi) for a faster deployment
</details>

<details>
  <summary><b>OROCHI 1.2.0  [2021/03/22]</b></summary>

  * Yara management
  * Symbols support check for linux/mac
  * Symbols download helper for missing ones
  * Improved dask logging
  * Added Bookmarks
  * Added MISP export
  * Clear cache when worker start (useful in swarm mode)
  * Added page autorefresh control
</details>

<details>
  <summary><b>OROCHI 1.1.0 [2020/10/29]</b></summary>

  * API: dump workflow can be done from api
  * Volatility: support for new file interface
</details>

<details>
  <summary><b>OROCHI 1.0.0 [2020/09/25]</b></summary>

  * execute Volatility 3 plugins and show results in table
  * plugins parameters support
  * custom template for timeliner, pstree
  * compare multiple plugin results in tabular format
  * compare 2 plugin results in json diff
  * automatic scan dump files with clamav and virustotal
  * automatic parsing of hives with regipy
</details>
