## Changelog
<details open>
  <summary><b>OROCHI 2.5.1</b></summary>

  * **Compact Activity & Worker Tasks Drawer with Live Dask Task Management**:
    * Merged the separate "History" and "Tasks" slide-overs into a single, unified tabbed **Activity Drawer** (`#activityDrawer`) accessible from a single navbar button.
    * Added real-time Dask task correlation in `/api/utils/dask_status`: tracks running tasks (`manage_upload`, `unzip`, running volatility plugins `run_plugin`, and system tasks in `TaskLog`).
    * Added Task Details inspection modal (`GET /api/utils/tasks/info/{task_id}`) displaying runtime duration, dump metadata, parameters, and worker node assignment.
    * Added Task Kill/Cancellation capability (`POST /api/utils/tasks/kill/{task_id}`) to cancel active Dask futures and gracefully update Django model statuses.
    * Real-time navbar indicator with running task counter, queued badge, and animated spinner.
  * **Folder Autocomplete & Seamless Creation**:
    * Integrated folder autocomplete with icon markers and folder item counts across Dump Create, Dump Edit, and Case modals.
    * Added automatic folder pre-creation on the fly: users can create a new folder directly from the dropdown or submit forms with new folder names without pre-registering them.
    * Normalized Pydantic v2 payload schema on `/api/dumps/` and `/api/cases/` to accept strings, dictionaries (`{"name": ...}` or `{"id": ...}`), integers, or `null`.
  * **Vendored Frontend Asset Manager & Automated Integrity Suite**:
    * Created `vendor_manifest.json` tracking pinned library versions, required code signatures, CDN source templates, and minimum size constraints.
    * Added `update_vendor_js` Django management command supporting `--check`, `--update`, `--dry-run`, `--package`, `--version-override`, and atomic rollback (`--rollback`).
    * Added automated test suite (`test_vendor_assets.py`) guaranteeing offline asset integrity and safe non-destructive updates.
  * **Core Frontend Upgrades & Performance Optimization**:
    * Upgraded jQuery from `3.5.1` to latest stable `3.7.1`.
    * Replaced legacy JSONEditor with modern `vanilla-jsoneditor` v3.13.0 featuring dark theme support and interactive tree/table/code modes.
    * Optimized page load performance by removing global Plotly.js overhead (~3.5MB download and parsing eliminated on global page loads), scoping it strictly to Timeliner analysis views.
  * **Case Detail Navigation & Dump Visual Recognition**:
    * Fixed results navigation bug when switching plugins with Case Detail view open (resolved DOM ID collision and detached memory node pointer).
    * Enhanced dump selection visibility: prominent 4px left accent border dynamically colored with `var(--dump-color)`, soft tinted row background, bold titles, and active checkmarks.
  * **DataTables & UI Modernization**:
    * Redesigned DataTables export controls (CSV, Excel, JSON, XML) with custom icons, tooltips, hover elevation, and dark mode styling.
    * Modern search input with magnifying glass icon and entries-per-page selector with custom SVG chevron.
    * Replaced legacy bitmap sort arrows with FontAwesome sort icons.
    * Wrapped analysis tables in modern card containers (`rounded-2xl border shadow-sm`).
    * Added rich empty and zero-records states with icons and guidance text.
    * Replaced basic chevrons with modern pill pagination.
    * Standardized Workbench action buttons (Bookmark, Compare, Rerun, Bodyfile) with neutral card styling and colored icons.
    * Fixed HTMX internal-data TypeError: Guarded `htmx.process` against `undefined`/`null`/empty collections across DataTables callbacks and sidebar refresh routines, patched null-safety in vendor HTMX, and added a defensive runtime wrapper in the base layout.
</details>

<details>
  <summary><b>OROCHI 2.5.0</b></summary>


  * Added Investigation Workspace Epic [[#1534](https://github.com/LDO-CERT/orochi/issues/1534)]
    * Case management with Findings and Evidence. [[#1536](https://github.com/LDO-CERT/orochi/issues/1536)]
    * Investigation Timeline tracking. [[#1538](https://github.com/LDO-CERT/orochi/issues/1538)]
    * Case Export to `.tar.gz` bundle. [[#1539](https://github.com/LDO-CERT/orochi/issues/1539)]
    * Capture The Flag (CTF) Mode. [[#1542](https://github.com/LDO-CERT/orochi/issues/1542)]
    * Automated Report Generation with customizable templates. [[#1540](https://github.com/LDO-CERT/orochi/issues/1540)]
    * Optional AI integration with Ollama for report summarization. [[#1540](https://github.com/LDO-CERT/orochi/issues/1540)]
  * Added MITRE ATT&CK tagging and Navigator layer export. [[#1541](https://github.com/LDO-CERT/orochi/issues/1541)]
    * Autocomplete and multi-technique tagging on Findings.
    * Interactive case-level ATT&CK 14-column Kill-Chain Matrix visualization with live filtering, full matrix heatmap mode, and technique findings inspector.
    * Export standard ATT&CK Navigator JSON layers (v4.5) with direct link to open in web navigator.
  * Added interactive Worker Tasks & Logs Drawer and extended UI task indicator.
    * Added task counter badges (running count + queued badge) and animated spinner indicator to the top navigation bar.
    * Slide-over "Worker Tasks & Logs" drawer showing connected Dask worker nodes (status, memory, threads, running jobs) and recent TaskLog entries with status badges.
    * Added one-click task re-run action directly from the Tasks Drawer and Django Admin.
    * Added robust Background Task Logging mechanism with admin visibility and transaction retry resilience.
  * Improved YARA Rules Synchronization & Storage:
    * Switched from monolithic 32k rule compilation to incremental block-by-block processing (500 rules per block) with immediate commits.
    * Added PostgreSQL NUL byte (`\x00`) sanitization to prevent aborted transactions on raw/binary rule files.
    * Added size guard to skip monolithic concatenated rule archives (>2MB) to prevent worker timeouts and memory exhaustion.
    * Added fallback discovery to populate local rule files when rulesets are already cloned on disk.
    * Added resilient git branch updating and error handling for remote repositories.
  * Added real-time websocket notifications to admins for background task completion/failure. [[#1566](https://github.com/LDO-CERT/orochi/issues/1566)]
  * Integrated `django-easy-audit` for comprehensive tracking of manual and automated database activities, including login events. [[#1563](https://github.com/LDO-CERT/orochi/issues/1563)]
  * Added `Host` concept for optionally linking related dumps/assets and performing diff comparisons.
  * Added external notifications system (Email, Webhook, Slack) configurable per-user via Account Settings.
  * Added DataTable export functionalities (CSV, Excel, JSON, XML).
  * Added "Restart all failed plugins" capability to the auto-restart plugin flow.
  * Fixed cache-building background task being triggered redundantly on all app instances and disabled `TaskLog` from auditing to reduce noise.
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
