# PostgreSQL Version Upgrade & Maintenance Guide

_Version 2.6.0 — 2026_  
_Comprehensive Administrator Reference for Safe Database Upgrades, Backups, and Disaster Recovery_

---

## Table of Contents

- [Overview](#overview)
- [Why PostgreSQL Major Upgrades Require Migration](#why-postgresql-major-upgrades-require-migration)
- [Quick Start: 1-Command Automated Upgrade](#quick-start-1-command-automated-upgrade)
- [Host-Level Automation Scripts](#host-level-automation-scripts)
  - [1. `upgrade_postgres.sh`](#1-upgradepostgressh)
  - [2. `backup_postgres.sh`](#2-backuppostgressh)
  - [3. `restore_postgres.sh`](#3-restorepostgressh)
- [Step-by-Step Manual Upgrade Walkthrough](#step-by-step-manual-upgrade-walkthrough)
- [In-Place Upgrade Alternative (`pg_upgrade --link`)](#in-place-upgrade-alternative-pgupgrade---link)
- [Disaster Recovery & Rollback Procedures](#disaster-recovery--rollback-procedures)
- [Post-Upgrade Verification Checklist](#post-upgrade-verification-checklist)
- [Automated Scheduled Backups (Cron)](#automated-scheduled-backups-cron)

---

## Overview

Orochi relies on **PostgreSQL** as its primary relational store for memory dump metadata, user roles, bookmarks, YARA rules, investigation cases, extracted IOCs, and background task logs.

Upgrading PostgreSQL across major versions (e.g., from PostgreSQL 15 or 16 to 17) requires updating the underlying disk catalog files. Simply bumping the container image tag without migrating data causes PostgreSQL to crash with:

```text
FATAL: database files are incompatible with server
DETAIL: The data directory was initialized by PostgreSQL version 16, which is not compatible with this version 17.X.
```

Orochi provides production-ready automation scripts in `scripts/postgres/` to perform safe, zero-data-loss upgrades with automatic volume snapshotting, verification, and rollback capabilities.

---

## Why PostgreSQL Major Upgrades Require Migration

PostgreSQL guarantees compatibility between minor versions (e.g., `16.1` → `16.2` → `16.6`), which can be upgraded simply by updating the image tag and restarting the container.

However, **major versions** (e.g., `15.x` → `16.x` or `16.x` → `17.x`) introduce changes to internal data structures, system catalogs, and transaction log formats:
1. **On-Disk Incompatibility**: The data files in `/var/lib/postgresql/data` cannot be opened directly by a newer major engine.
2. **Global Objects**: Single database dumps (`pg_dump`) omit system users, passwords, and tablespaces. A full cluster dump (`pg_dumpall`) is required to preserve application authentication and permissions.
3. **Query Optimizer Statistics**: After migrating data to a new major version, query plans may be sub-optimal until `VACUUM ANALYZE` is executed.

---

## Quick Start: 1-Command Automated Upgrade

To upgrade PostgreSQL safely with full volume snapshotting and verification:

```bash
# Run the automated upgrade to PostgreSQL 17
./scripts/postgres/upgrade_postgres.sh --to 17.4
```

### What `upgrade_postgres.sh` does automatically:
1. **Pre-flight Checks**: Validates Docker environment, current PostgreSQL version, and disk space.
2. **Quiesce Writers**: Stops Django WSGI, ASGI, and Dask workers to guarantee zero transaction loss.
3. **Full Cluster Dump**: Captures all roles, databases, and schema objects via `pg_dumpall --clean`.
4. **Safety Snapshot**: Creates an immutable Docker volume clone (e.g. `orochi_local_postgres_data_backup_v16_<timestamp>`). Old data is **never** deleted.
5. **Recreate & Start**: Starts PostgreSQL with the new version image tag on an initialized volume.
6. **Restore Data**: Streams the compressed cluster dump into the new PostgreSQL engine.
7. **Optimize**: Executes `VACUUM ANALYZE` across the database to refresh planner statistics.
8. **Verify & Resume**: Confirms table counts, tests Django database connectivity, and restarts all services.
9. **Automatic Rollback**: If any failure occurs during migration, restores original volumes and images automatically.

---

## Host-Level Automation Scripts

All scripts are located in `scripts/postgres/` and require only Bash and Docker on the host machine.

### 1. `upgrade_postgres.sh`

Automates the complete end-to-end upgrade workflow.

```bash
./scripts/postgres/upgrade_postgres.sh [options]
```

#### Options:
| Flag | Description | Default |
|---|---|---|
| `-t, --to VERSION` | Target PostgreSQL version (e.g. `17.4`, `17`, `16.2`) | Interactive prompt |
| `-c, --container NAME` | PostgreSQL container name | `orochi_postgres` |
| `-v, --volume NAME` | Docker data volume name | Auto-detected from container |
| `-b, --backup-dir DIR` | Output directory for migration dump | `./backups/upgrade` |
| `--dry-run` | Simulate all steps without modifying containers or volumes | `false` |
| `--no-prompt` | Run non-interactively (ideal for CI/CD or automation) | `false` |
| `-h, --help` | Show command usage and options | |

#### Examples:
```bash
# Test upgrade plan without making any changes
./scripts/postgres/upgrade_postgres.sh --to 17.4 --dry-run

# Non-interactive automated upgrade
./scripts/postgres/upgrade_postgres.sh --to 17.4 --no-prompt
```

---

### 2. `backup_postgres.sh`

Produces compressed, timestamped backups from the running PostgreSQL container.

```bash
./scripts/postgres/backup_postgres.sh [options]
```

#### Options:
| Flag | Description | Default |
|---|---|---|
| `-c, --container NAME` | Container name | Auto-detected (`orochi_postgres`) |
| `-o, --output-dir DIR` | Destination directory on host | `./backups` |
| `-d, --database NAME` | Single database to dump | Full cluster (`pg_dumpall`) |
| `-u, --user NAME` | PostgreSQL username | Auto-detected (`debug`) |
| `-h, --help` | Show command usage and options | |

#### Examples:
```bash
# Full cluster backup (all databases + roles)
./scripts/postgres/backup_postgres.sh

# Single database backup to custom directory
./scripts/postgres/backup_postgres.sh -d orochi -o /mnt/backups/orochi
```

---

### 3. `restore_postgres.sh`

Restores a `.sql` or `.sql.gz` dump into PostgreSQL with connection dropping and pre-restore snapshots.

```bash
./scripts/postgres/restore_postgres.sh [options] <backup_file>
```

#### Options:
| Flag | Description | Default |
|---|---|---|
| `-f, --file FILE` | Path to backup file (`.sql` or `.sql.gz`) | Positional argument |
| `-c, --container NAME` | Target container name | Auto-detected |
| `-d, --database NAME` | Target database name | `orochi` |
| `--no-snapshot` | Skip creating a pre-restore safety snapshot | `false` |
| `-h, --help` | Show command usage and options | |

#### Examples:
```bash
# Restore from a compressed cluster backup
./scripts/postgres/restore_postgres.sh ./backups/postgres_cluster_20260911_115049.sql.gz
```

---

## Step-by-Step Manual Upgrade Walkthrough

If you prefer to perform the upgrade manually without running `upgrade_postgres.sh`:

### Step 1: Quiesce Application Writers
Stop web and background worker containers so no transactions are committed during export:
```bash
docker stop orochi_django_wsgi orochi_django_asgi orochi-worker-1 orochi-worker-2 orochi_scheduler
```

### Step 2: Export Full Cluster SQL Dump
Capture all databases, roles, and schema definitions:
```bash
mkdir -p ./backups/manual_upgrade
docker exec -e PGPASSWORD=debug orochi_postgres pg_dumpall -U debug --clean --if-exists | gzip -9 > ./backups/manual_upgrade/cluster_pre_upgrade.sql.gz
```

### Step 3: Snapshot the Current Data Volume
Preserve an exact copy of the raw volume files:
```bash
docker volume create orochi_local_postgres_data_v16_snapshot
docker run --rm \
  -v orochi_local_postgres_data:/from:ro \
  -v orochi_local_postgres_data_v16_snapshot:/to \
  alpine cp -a /from/. /to/
```

### Step 4: Recreate the Data Volume
Stop and remove the old database container, then re-create an empty volume:
```bash
docker stop orochi_postgres && docker rm orochi_postgres
docker volume rm orochi_local_postgres_data
docker volume create orochi_local_postgres_data
```

### Step 5: Start PostgreSQL with the Target Version
Update your `.env` file or export `POSTGRES_VERSION`:
```bash
export POSTGRES_VERSION=17.4
docker compose up -d postgres
```
Wait until PostgreSQL is healthy:
```bash
docker exec orochi_postgres pg_isready -U debug
```

### Step 6: Restore the Cluster Dump
Stream the SQL dump into the newly initialized instance:
```bash
gunzip -c ./backups/manual_upgrade/cluster_pre_upgrade.sql.gz | docker exec -i -e PGPASSWORD=debug orochi_postgres psql -U debug -d postgres
```

### Step 7: Update Query Planner Statistics
```bash
docker exec -e PGPASSWORD=debug orochi_postgres psql -U debug -d orochi -c "VACUUM ANALYZE;"
```

### Step 8: Resume Application Services
```bash
docker compose up -d
docker exec orochi_django_wsgi python manage.py showmigrations
```

---

## In-Place Upgrade Alternative (`pg_upgrade --link`)

For massive databases (e.g. hundreds of gigabytes), dumping and restoring via SQL text files can take hours. An alternative approach is using PostgreSQL's native `pg_upgrade` utility with hard links (`--link`), which completes in seconds without duplicating disk space.

Orochi supports in-place upgrades using the official multi-version upgrade container [`tianon/postgres-upgrade`](https://github.com/tianon/docker-postgres-upgrade):

```bash
# 1. Stop the Orochi stack
docker compose down

# 2. Rename old volume for upgrade processing
docker volume create orochi_local_postgres_data_new

# 3. Run in-place pg_upgrade (e.g. 16 to 17)
docker run --rm \
  -v orochi_local_postgres_data:/var/lib/postgresql/16/data \
  -v orochi_local_postgres_data_new:/var/lib/postgresql/17/data \
  tianon/postgres-upgrade:16-to-17 --link

# 4. Swap volume and start stack with new version
docker volume rm orochi_local_postgres_data
docker volume create orochi_local_postgres_data
docker run --rm \
  -v orochi_local_postgres_data_new:/from:ro \
  -v orochi_local_postgres_data:/to \
  alpine cp -a /from/. /to/
docker volume rm orochi_local_postgres_data_new

export POSTGRES_VERSION=17.4
docker compose up -d
```

---

## Disaster Recovery & Rollback Procedures

If an upgrade fails or an unforeseen regression is detected after upgrading:

### 1. Rollback from Snapshot Volume
If you upgraded using `upgrade_postgres.sh`, your previous volume was preserved under a snapshot name (e.g. `orochi_local_postgres_data_backup_v16_<timestamp>`):

```bash
# Stop all services
docker compose down

# Re-create primary data volume from snapshot
docker volume rm orochi_local_postgres_data
docker volume create orochi_local_postgres_data
docker run --rm \
  -v orochi_local_postgres_data_backup_v16_<timestamp>:/from:ro \
  -v orochi_local_postgres_data:/to \
  alpine cp -a /from/. /to/

# Revert image tag and restart
export POSTGRES_VERSION=16.2
docker compose up -d
```

### 2. Rollback from SQL Backup Archive
```bash
# Clean database volume
docker compose stop postgres
docker volume rm orochi_local_postgres_data
docker volume create orochi_local_postgres_data

# Start target container version
export POSTGRES_VERSION=16.2
docker compose up -d postgres

# Restore backup
./scripts/postgres/restore_postgres.sh ./backups/upgrade/postgres_cluster_v16_to_v17_<timestamp>.sql.gz
```

---

## Post-Upgrade Verification Checklist

After completing the upgrade, verify the integrity of the database:

- [ ] **Container Status**: `docker ps --filter name=postgres` shows status `Up`.
- [ ] **Server Version**: `docker exec orochi_postgres psql -U debug -c "SHOW server_version;"` returns the target version.
- [ ] **Table Count**: Confirm table count matches pre-upgrade count:
  ```bash
  docker exec -e PGPASSWORD=debug orochi_postgres psql -U debug -d orochi -c \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';"
  ```
- [ ] **Django Migrations**: Check that all migrations are recognized as applied:
  ```bash
  docker exec orochi_django_wsgi python manage.py showmigrations
  ```
- [ ] **GIN & Full-Text Search Indexes**: Verify search indexing operates normally:
  ```bash
  docker exec orochi_django_wsgi pytest orochi/api/tests/test_search_api.py -v
  ```
- [ ] **Web UI Access**: Navigate to `https://localhost` and confirm dump lists, process trees, and analysis results load properly.

---

## Automated Scheduled Backups (Cron)

To schedule automated daily backups on the host system:

1. Open crontab for editing:
   ```bash
   crontab -e
   ```
2. Add a daily entry at 02:00 AM (keeps the last 14 days of compressed backups):
   ```bash
   0 2 * * * /home/dadokkio/Docker/NOSTRI/orochi/scripts/postgres/backup_postgres.sh -o /home/dadokkio/Docker/NOSTRI/orochi/backups >> /var/log/orochi_postgres_backup.log 2>&1
   0 3 * * * find /home/dadokkio/Docker/NOSTRI/orochi/backups -name "postgres_cluster_*.sql.gz" -mtime +14 -delete
   ```
