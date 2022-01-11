# OROCHI 1.3.1 [wip]
- Unzip password protected file [#484](https://github.com/LDO-CERT/orochi/issues/484)
- Md5 support for dumped files [#489](https://github.com/LDO-CERT/orochi/issues/489)
- Improve elasticsearch details [#462](https://github.com/LDO-CERT/orochi/issues/462)
- Add info for uploaded dumps [#488](https://github.com/LDO-CERT/orochi/issues/488)

### OROCHI 1.3.0 [2021/10/02]
- Manage custom plugins [#245](https://github.com/LDO-CERT/orochi/issues/245)
- YARA rules management [#28](https://github.com/LDO-CERT/orochi/issues/28)
- Manage results with more than 10k rows [#3](https://github.com/LDO-CERT/orochi/issues/3)
- Added docker-compose for swarm [#252](https://github.com/LDO-CERT/orochi/issues/252) with documentation [#257](https://github.com/LDO-CERT/orochi/issues/257)
- Improved search [#271](https://github.com/LDO-CERT/orochi/issues/271)
- Use multi-stage builds [#242](https://github.com/LDO-CERT/orochi/issues/242)
- Pre built images available on [ghcr](https://github.com/orgs/LDO-CERT/packages?repo_name=orochi) for a faster deployment

### OROCHI 1.2.0  [2021/03/22]:
- Yara management
- Symbols support check for linux/mac
- Symbols download helper for missing ones
- Improved dask logging
- Added Bookmarks
- Added MISP export
- Clear cache when worker start (useful in swarm mode)
- Added page autorefresh control

### OROCHI 1.1.0 [2020/10/29]:
- API: dump workflow can be done from api
- Volatility: support for new file interface

### OROCHI 1.0.0 [2020/09/25]:
- execute Volatility 3 plugins and show results in table
- plugins parameters support
- custom template for timeliner, pstree
- compare multiple plugin results in tabular format
- compare 2 plugin results in json diff
- automatic scan dump files with clamav and virustotal
- automatic parsing of hives with regipy
