## Changelog

<details open>
  <summary><b>OROCHI 2.3.0</b></summary>

  * signal for dump/result changes are very verbose [[#1074](https://github.com/LDO-CERT/orochi/issues/1074)]
  * replace drf & co. with django-ninja [[#1073](https://github.com/LDO-CERT/orochi/issues/1073)]
  * Add experimental support for ARM64
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
