#!/usr/bin/env bash
# ==============================================================================
# Orochi - PostgreSQL Host Backup Script
# ==============================================================================
# Usage:
#   ./scripts/postgres/backup_postgres.sh [options]
#
# Options:
#   -c, --container NAME   Container name (default: auto-detect or orochi_postgres)
#   -o, --output-dir DIR   Directory to store backup (default: ./backups)
#   -d, --database NAME    Specific database name (default: full cluster via pg_dumpall)
#   -u, --user NAME        PostgreSQL username (default: auto-detected or debug)
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

# Defaults
CONTAINER_NAME=""
OUTPUT_DIR="./backups"
TARGET_DB=""
PG_USER=""
CLUSTER_MODE=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--container)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--database)
            TARGET_DB="$2"
            CLUSTER_MODE=false
            shift 2
            ;;
        -u|--user)
            PG_USER="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,15p' "$0" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

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

# Detect user if not specified
if [[ -z "${PG_USER}" ]]; then
    PG_USER="$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_USER 2>/dev/null || echo "debug")"
fi

# Detect default DB if in single-database mode without explicit name
if [[ "${CLUSTER_MODE}" == false && -z "${TARGET_DB}" ]]; then
    TARGET_DB="$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_DB 2>/dev/null || echo "orochi")"
fi

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
START_TIME="$(date +%s)"

if [[ "${CLUSTER_MODE}" == true ]]; then
    BACKUP_FILE="${OUTPUT_DIR}/postgres_cluster_${TIMESTAMP}.sql.gz"
    log_info "Initiating full cluster backup (roles, tablespaces, databases) from '${CONTAINER_NAME}'..."

    # Execute pg_dumpall via docker exec and stream to gzip
    docker exec -e PGPASSWORD="$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_PASSWORD 2>/dev/null || echo "debug")" \
        "${CONTAINER_NAME}" pg_dumpall -U "${PG_USER}" --clean --if-exists | gzip -9 > "${BACKUP_FILE}"
else
    BACKUP_FILE="${OUTPUT_DIR}/postgres_${TARGET_DB}_${TIMESTAMP}.sql.gz"
    log_info "Initiating database backup of '${TARGET_DB}' from '${CONTAINER_NAME}'..."

    # Execute pg_dump via docker exec and stream to gzip
    docker exec -e PGPASSWORD="$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_PASSWORD 2>/dev/null || echo "debug")" \
        "${CONTAINER_NAME}" pg_dump -U "${PG_USER}" -d "${TARGET_DB}" --clean --if-exists --format=plain | gzip -9 > "${BACKUP_FILE}"
fi

# Verify backup integrity
if [[ ! -s "${BACKUP_FILE}" ]]; then
    log_error "Backup file '${BACKUP_FILE}' is empty or was not created!"
    rm -f "${BACKUP_FILE}"
    exit 1
fi

if ! gzip -t "${BACKUP_FILE}" 2>/dev/null; then
    log_error "Backup file '${BACKUP_FILE}' failed gzip integrity verification!"
    exit 1
fi

END_TIME="$(date +%s)"
DURATION=$((END_TIME - START_TIME))
FILE_SIZE="$(du -h "${BACKUP_FILE}" | cut -f1)"

# Check table count
TABLE_COUNT=$(docker exec -e PGPASSWORD="$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_PASSWORD 2>/dev/null || echo "debug")" \
    "${CONTAINER_NAME}" psql -U "${PG_USER}" -d orochi -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null || echo "N/A")

log_success "Backup completed successfully in ${DURATION}s"
echo -e "  ${CYAN}File:${NC}        ${BACKUP_FILE}"
echo -e "  ${CYAN}Size:${NC}        ${FILE_SIZE}"
echo -e "  ${CYAN}Tables:${NC}      ${TABLE_COUNT} public tables in 'orochi'"
echo -e "  ${CYAN}Container:${NC}   ${CONTAINER_NAME}"
echo -e "  ${CYAN}Mode:${NC}        $([[ "${CLUSTER_MODE}" == true ]] && echo "Full Cluster (pg_dumpall)" || echo "Single Database (${TARGET_DB})")"
