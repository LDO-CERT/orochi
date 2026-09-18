#!/usr/bin/env bash
# ==============================================================================
# Orochi - PostgreSQL Host Restore Script
# ==============================================================================
# Usage:
#   ./scripts/postgres/restore_postgres.sh [options] <backup_file>
#
# Options:
#   -f, --file FILE        Path to backup file (.sql or .sql.gz)
#   -c, --container NAME   Container name (default: auto-detect or orochi_postgres)
#   -d, --database NAME    Target database name (default: auto-detected or orochi)
#   -u, --user NAME        PostgreSQL username (default: auto-detected or debug)
#   --no-snapshot          Skip creating a pre-restore safety backup
#   -h, --help             Show this help message
# ==============================================================================

set -o errexit
set -o pipefail
set -o nounset

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

CONTAINER_NAME=""
BACKUP_FILE=""
TARGET_DB=""
PG_USER=""
TAKE_SNAPSHOT=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            BACKUP_FILE="$2"
            shift 2
            ;;
        -c|--container)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        -d|--database)
            TARGET_DB="$2"
            shift 2
            ;;
        -u|--user)
            PG_USER="$2"
            shift 2
            ;;
        --no-snapshot)
            TAKE_SNAPSHOT=false
            shift 1
            ;;
        -h|--help)
            sed -n '2,16p' "$0" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
        *)
            if [[ -z "${BACKUP_FILE}" ]]; then
                BACKUP_FILE="$1"
                shift 1
            else
                log_error "Unexpected argument: $1"
                exit 1
            fi
            ;;
    esac
done

# Validate backup file
if [[ -z "${BACKUP_FILE}" ]]; then
    log_error "No backup file specified. Provide a path to a .sql or .sql.gz backup file."
    echo "Usage: $0 [options] <backup_file>"
    exit 1
fi

if [[ ! -f "${BACKUP_FILE}" ]]; then
    log_error "Backup file '${BACKUP_FILE}' does not exist."
    exit 1
fi

# Check Docker availability
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not available in PATH."
    exit 1
fi

# Detect running postgres container if not provided
if [[ -z "${CONTAINER_NAME}" ]]; then
    if docker ps --format '{{.Names}}' | grep -E '^orochi_postgres$' &> /dev/null; then
        CONTAINER_NAME="orochi_postgres"
    elif docker ps --format '{{.Names}}' | grep -E 'postgres' &> /dev/null; then
        CONTAINER_NAME="$(docker ps --format '{{.Names}}' | grep -E 'postgres' | head -n 1)"
    else
        log_error "No running PostgreSQL container found. Is the Orochi stack running?"
        exit 1
    fi
fi

# Verify container is running
if ! docker ps --format '{{.Names}}' | grep -Fxq "${CONTAINER_NAME}"; then
    log_error "Container '${CONTAINER_NAME}' is not running."
    exit 1
fi

# Detect user & DB
if [[ -z "${PG_USER}" ]]; then
    PG_USER="$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_USER 2>/dev/null || echo "debug")"
fi
if [[ -z "${TARGET_DB}" ]]; then
    TARGET_DB="$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_DB 2>/dev/null || echo "orochi")"
fi

PG_PASS="$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_PASSWORD 2>/dev/null || echo "debug")"

# Pre-restore safety snapshot
if [[ "${TAKE_SNAPSHOT}" == true ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -x "${SCRIPT_DIR}/backup_postgres.sh" ]]; then
        log_info "Creating pre-restore safety snapshot..."
        "${SCRIPT_DIR}/backup_postgres.sh" --container "${CONTAINER_NAME}" --output-dir "./backups/pre_restore_snapshots"
    fi
fi

START_TIME="$(date +%s)"
log_info "Preparing to restore from '${BACKUP_FILE}' into container '${CONTAINER_NAME}'..."

# Verify gzip integrity if compressed
IS_GZIP=false
if file "${BACKUP_FILE}" | grep -q "gzip compressed"; then
    IS_GZIP=true
    if ! gzip -t "${BACKUP_FILE}" 2>/dev/null; then
        log_error "Corrupted gzip file '${BACKUP_FILE}'."
        exit 1
    fi
fi

# Inspect first few lines of backup to determine if it is pg_dumpall or single db
HEAD_LINES="$([[ "${IS_GZIP}" == true ]] && zcat "${BACKUP_FILE}" 2>/dev/null | head -n 30 || head -n 30 "${BACKUP_FILE}")"
IS_CLUSTER_DUMP=false
if echo "${HEAD_LINES}" | grep -qiE "(pg_dumpall|CREATE ROLE|\\connect postgres)"; then
    IS_CLUSTER_DUMP=true
fi

# Terminate active client connections to avoid lock conflicts
log_info "Terminating active connections to '${TARGET_DB}'..."
docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" \
    psql -U "${PG_USER}" -d postgres -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${TARGET_DB}' AND pid <> pg_backend_pid();" &> /dev/null || true

# Execute restore
if [[ "${IS_CLUSTER_DUMP}" == true ]]; then
    log_info "Applying full cluster dump (roles, tablespaces, databases)..."
    if [[ "${IS_GZIP}" == true ]]; then
        gunzip -c "${BACKUP_FILE}" | docker exec -i -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" psql -U "${PG_USER}" -d postgres -q
    else
        docker exec -i -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" psql -U "${PG_USER}" -d postgres -q < "${BACKUP_FILE}"
    fi
else
    log_info "Applying database dump to '${TARGET_DB}'..."
    # Ensure database exists
    docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" psql -U "${PG_USER}" -d postgres -tc \
        "SELECT 1 FROM pg_database WHERE datname = '${TARGET_DB}'" | grep -q 1 || \
        docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" createdb -U "${PG_USER}" "${TARGET_DB}"

    if [[ "${IS_GZIP}" == true ]]; then
        gunzip -c "${BACKUP_FILE}" | docker exec -i -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" psql -U "${PG_USER}" -d "${TARGET_DB}" -q
    else
        docker exec -i -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" psql -U "${PG_USER}" -d "${TARGET_DB}" -q < "${BACKUP_FILE}"
    fi
fi

# Run VACUUM ANALYZE to update optimizer statistics
log_info "Rebuilding query planner statistics (VACUUM ANALYZE)..."
docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" \
    psql -U "${PG_USER}" -d "${TARGET_DB}" -c "VACUUM ANALYZE;" &> /dev/null || true

END_TIME="$(date +%s)"
DURATION=$((END_TIME - START_TIME))

# Verify database health
TABLE_COUNT=$(docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" \
    psql -U "${PG_USER}" -d "${TARGET_DB}" -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null || echo "N/A")

log_success "Database restore completed in ${DURATION}s"
echo -e "  ${CYAN}Source File:${NC}  ${BACKUP_FILE}"
echo -e "  ${CYAN}Container:${NC}    ${CONTAINER_NAME}"
echo -e "  ${CYAN}Database:${NC}     ${TARGET_DB}"
echo -e "  ${CYAN}Tables:${NC}       ${TABLE_COUNT} public tables in '${TARGET_DB}'"
