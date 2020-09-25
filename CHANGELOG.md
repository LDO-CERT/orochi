# OROCHI 1.0b

## News:

- execute Volatility 3 plugins and show results in table
- plugins parameters support
- custom template for timeliner, pstree
- compare multiple plugin results in tabular format
- compare 2 plugin results in json diff
- automatic scan dump files with clamav and virustotal
- automatic parsing of hives with regipy

## Supported libs:

- volatility 3 v. 1.2.1-beta.1
- elastic 7.9.x


## Bug Fixes:
- some data are failing during elastic bulk import #15
- authorized_users in class EditDumpForm breaks migrations when install from scratch #65
- plugins support dump if not set #73
