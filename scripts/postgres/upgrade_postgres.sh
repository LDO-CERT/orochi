#!/usr/bin/env bash
# ==============================================================================
# Orochi - PostgreSQL Automated Version Upgrade Script
# ==============================================================================
# Usage:
#   ./scripts/postgres/upgrade_postgres.sh [options]
#
# Options:
#   -t, --to VERSION       Target PostgreSQL version (e.g. 17, 17.4, 16.2)
#   -c, --container NAME   PostgreSQL container name (default: orochi_postgres)
#   -v, --volume NAME      PostgreSQL volume name (default: auto-detected)
#   -f, --compose-file YML Compose file path (default: docker-compose.yml)
#   -b, --backup-dir DIR   Directory for migration backup (default: ./backups/upgrade)
#   --dry-run              Simulate the upgrade process without making changes
#   --no-prompt            Proceed without interactive confirmation
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
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "\n${BOLD}${CYAN}==>${NC} ${BOLD}$*${NC}"; }

TARGET_VERSION=""
CONTAINER_NAME="orochi_postgres"
VOLUME_NAME=""
COMPOSE_FILE="docker-compose.yml"
BACKUP_DIR="./backups/upgrade"
DRY_RUN=false
NO_PROMPT=false

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--to)
            TARGET_VERSION="$2"
            shift 2
            ;;
        -c|--container)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        -v|--volume)
            VOLUME_NAME="$2"
            shift 2
            ;;
        -f|--compose-file)
            COMPOSE_FILE="$2"
            shift 2
            ;;
        -b|--backup-dir)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift 1
            ;;
        --no-prompt)
            NO_PROMPT=true
            shift 1
            ;;
        -h|--help)
            sed -n '2,17p' "$0" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

# Check Docker CLI
if ! command -v docker &> /dev/null; then
    log_error "Docker is required but not installed or not in PATH."
    exit 1
fi

COMPOSE_CMD=""
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    log_error "Neither 'docker compose' nor 'docker-compose' was found."
    exit 1
fi

# Detect running postgres container
if ! docker ps --format '{{.Names}}' | grep -Fxq "${CONTAINER_NAME}"; then
    log_error "Container '${CONTAINER_NAME}' is not currently running. Start the Orochi stack before upgrading."
    exit 1
fi

# Detect current PostgreSQL version
log_step "1. Detecting Current PostgreSQL Installation"
CURRENT_FULL_VER=$(docker exec "${CONTAINER_NAME}" psql -U debug -d postgres -t -A -c "SHOW server_version;" 2>/dev/null || \
                  docker exec "${CONTAINER_NAME}" postgres -V 2>/dev/null | awk '{print $NF}' || echo "unknown")
CURRENT_MAJOR=$(echo "${CURRENT_FULL_VER}" | cut -d. -f1)

log_info "Active container:      ${CONTAINER_NAME}"
log_info "Detected server:       PostgreSQL ${CURRENT_FULL_VER} (Major: ${CURRENT_MAJOR})"

if [[ -z "${TARGET_VERSION}" ]]; then
    if [[ "${NO_PROMPT}" == true ]]; then
        log_error "Target version must be specified via --to when running with --no-prompt."
        exit 1
    fi
    echo ""
    read -r -p "Enter target PostgreSQL version (e.g. 17.4 or 17): " TARGET_VERSION
fi

if [[ -z "${TARGET_VERSION}" ]]; then
    log_error "Target PostgreSQL version cannot be empty."
    exit 1
fi

TARGET_MAJOR=$(echo "${TARGET_VERSION}" | cut -d. -f1)
log_info "Target version:        PostgreSQL ${TARGET_VERSION} (Major: ${TARGET_MAJOR})"

if [[ "${CURRENT_MAJOR}" == "${TARGET_MAJOR}" ]]; then
    log_warn "Current major version (${CURRENT_MAJOR}) already matches target major version (${TARGET_MAJOR})."
    log_warn "In-place minor version bumps do not alter the on-disk data format and do not require volume migration."
    if [[ "${NO_PROMPT}" == false ]]; then
        read -r -p "Do you still want to proceed with full dump/restore migration? [y/N]: " CONFIRM_SAME
        if [[ ! "${CONFIRM_SAME}" =~ ^[Yy]$ ]]; then
            log_info "Upgrade cancelled by user."
            exit 0
        fi
    fi
fi

# Detect volume name
if [[ -z "${VOLUME_NAME}" ]]; then
    VOLUME_NAME=$(docker inspect "${CONTAINER_NAME}" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}')
    if [[ -z "${VOLUME_NAME}" ]]; then
        VOLUME_NAME="orochi_local_postgres_data"
    fi
fi
log_info "Data volume:           ${VOLUME_NAME}"

# Detect postgres credentials from container env
PG_USER=$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_USER 2>/dev/null || echo "debug")
PG_PASS=$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_PASSWORD 2>/dev/null || echo "debug")
PG_DB=$(docker exec "${CONTAINER_NAME}" printenv POSTGRES_DB 2>/dev/null || echo "orochi")

# Pre-upgrade public table count
PRE_TABLE_COUNT=$(docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" \
    psql -U "${PG_USER}" -d "${PG_DB}" -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null || echo "0")
log_info "Pre-upgrade tables:    ${PRE_TABLE_COUNT} public tables in '${PG_DB}'"

# Pull target image to verify existence before touching anything
log_step "2. Pre-flight Verification & Image Download"
log_info "Validating and pulling 'postgres:${TARGET_VERSION}' image..."
if [[ "${DRY_RUN}" == false ]]; then
    if ! docker pull "postgres:${TARGET_VERSION}"; then
        log_error "Failed to pull image 'postgres:${TARGET_VERSION}'. Please verify the version tag."
        exit 1
    fi
else
    log_info "[DRY-RUN] Would pull image 'postgres:${TARGET_VERSION}'"
fi

TIMESTAMP=$(date +'%Y%m%d_%H%M%S')
SNAPSHOT_VOLUME="${VOLUME_NAME}_backup_v${CURRENT_MAJOR}_${TIMESTAMP}"
MIGRATION_DUMP="${BACKUP_DIR}/postgres_cluster_v${CURRENT_MAJOR}_to_v${TARGET_MAJOR}_${TIMESTAMP}.sql.gz"

echo ""
echo -e "${BOLD}================================================================${NC}"
echo -e "                 ${BOLD}UPGRADE PLAN SUMMARY${NC}"
echo -e "${BOLD}================================================================${NC}"
echo -e "  ${CYAN}Source Version:${NC}      PostgreSQL ${CURRENT_FULL_VER}"
echo -e "  ${CYAN}Target Version:${NC}      PostgreSQL ${TARGET_VERSION}"
echo -e "  ${CYAN}Active Volume:${NC}       ${VOLUME_NAME}"
echo -e "  ${CYAN}Safety Snapshot:${NC}     ${SNAPSHOT_VOLUME} (preserved forever)"
echo -e "  ${CYAN}Cluster Dump:${NC}        ${MIGRATION_DUMP}"
echo -e "  ${CYAN}Writers Quiesced:${NC}    Django WSGI, ASGI, Dask Workers"
echo -e "  ${CYAN}Post-Restore:${NC}        VACUUM ANALYZE & Django migration check"
echo -e "${BOLD}================================================================${NC}"
echo ""

if [[ "${DRY_RUN}" == true ]]; then
    log_info "[DRY-RUN] Simulation mode enabled. No changes will be made to containers or volumes."
    exit 0
fi

if [[ "${NO_PROMPT}" == false ]]; then
    read -r -p "Are you sure you want to execute the upgrade now? [y/N]: " PROCEED
    if [[ ! "${PROCEED}" =~ ^[Yy]$ ]]; then
        log_info "Upgrade aborted by user."
        exit 0
    fi
fi

# Track state for rollback handler
ROLLBACK_NEEDED=false
PREV_CONTAINER_IMAGE=$(docker inspect "${CONTAINER_NAME}" --format '{{.Config.Image}}')
WRITERS_STOPPED=false

cleanup_rollback() {
    if [[ "${ROLLBACK_NEEDED}" == true ]]; then
        log_error "\nUpgrade failed! Initiating automatic rollback..."

        # Stop new container if created
        docker stop "${CONTAINER_NAME}" &> /dev/null || true
        docker rm "${CONTAINER_NAME}" &> /dev/null || true

        # Revert volume from snapshot if snapshot exists
        if docker volume inspect "${SNAPSHOT_VOLUME}" &> /dev/null; then
            log_warn "Restoring original data volume from snapshot '${SNAPSHOT_VOLUME}'..."
            docker volume rm "${VOLUME_NAME}" &> /dev/null || true
            docker volume create "${VOLUME_NAME}" &> /dev/null || true
            docker run --rm -v "${SNAPSHOT_VOLUME}:/from:ro" -v "${VOLUME_NAME}:/to" alpine cp -a /from/. /to/ &> /dev/null || true
        fi

        # Start original container image
        log_warn "Restarting database with original image '${PREV_CONTAINER_IMAGE}'..."
        ${COMPOSE_CMD} up -d postgres &> /dev/null || true

        # Restart all services if writers were stopped
        if [[ "${WRITERS_STOPPED}" == true ]]; then
            log_warn "Restarting application stack..."
            ${COMPOSE_CMD} up -d &> /dev/null || true
        fi

        log_error "Rollback complete. System state has been restored to PostgreSQL ${CURRENT_FULL_VER}."
    fi
}
trap cleanup_rollback EXIT

ROLLBACK_NEEDED=true

# Step 3: Quiesce writers
log_step "3. Quiescing Database Writers"
WRITER_CONTAINERS=$(docker ps --format '{{.Names}}' | grep -E '^(orochi_django_wsgi|orochi_django_asgi|orochi-worker-.*|orochi_scheduler)$' || true)
if [[ -n "${WRITER_CONTAINERS}" ]]; then
    log_info "Stopping database clients: ${WRITER_CONTAINERS//$'\n'/, }..."
    docker stop ${WRITER_CONTAINERS}
    WRITERS_STOPPED=true
else
    log_info "No active web or worker containers found to stop."
fi

# Step 4: Full Cluster Dump
log_step "4. Exporting Full Cluster SQL Dump (pg_dumpall)"
mkdir -p "${BACKUP_DIR}"
DUMP_START=$(date +%s)
docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" \
    pg_dumpall -U "${PG_USER}" --clean --if-exists | gzip -9 > "${MIGRATION_DUMP}"

if [[ ! -s "${MIGRATION_DUMP}" ]] || ! gzip -t "${MIGRATION_DUMP}" 2>/dev/null; then
    log_error "Cluster dump failed or file is corrupted: ${MIGRATION_DUMP}"
    exit 1
fi
DUMP_END=$(date +%s)
log_success "Exported $(du -h "${MIGRATION_DUMP}" | cut -f1) in $((DUMP_END - DUMP_START))s."

# Step 5: Snapshot Volume Preservation
log_step "5. Creating Safety Snapshot of Volume '${VOLUME_NAME}'"
log_info "Snapshot volume: '${SNAPSHOT_VOLUME}'..."
docker volume create "${SNAPSHOT_VOLUME}" > /dev/null
docker run --rm -v "${VOLUME_NAME}:/from:ro" -v "${SNAPSHOT_VOLUME}:/to" alpine cp -a /from/. /to/
log_success "Volume snapshot preserved successfully."

# Step 6: Container & Volume Re-creation
log_step "6. Recreating Volume & Starting PostgreSQL ${TARGET_VERSION}"
docker stop "${CONTAINER_NAME}" > /dev/null
docker rm "${CONTAINER_NAME}" > /dev/null
docker volume rm "${VOLUME_NAME}" > /dev/null
docker volume create "${VOLUME_NAME}" > /dev/null

# Update POSTGRES_VERSION in .env if present or pass environment override
if [[ -f ".env" ]] && grep -q "^POSTGRES_VERSION=" .env; then
    sed -i "s/^POSTGRES_VERSION=.*/POSTGRES_VERSION=${TARGET_VERSION}/" .env
elif [[ -f ".env" ]]; then
    echo "POSTGRES_VERSION=${TARGET_VERSION}" >> .env
fi

export POSTGRES_VERSION="${TARGET_VERSION}"
${COMPOSE_CMD} up -d postgres

log_info "Waiting for new PostgreSQL instance to be ready..."
READY=false
for i in {1..30}; do
    if docker exec "${CONTAINER_NAME}" pg_isready -U "${PG_USER}" &> /dev/null; then
        READY=true
        break
    fi
    sleep 2
done

if [[ "${READY}" == false ]]; then
    log_error "PostgreSQL ${TARGET_VERSION} failed to become ready within 60 seconds."
    exit 1
fi
log_success "PostgreSQL ${TARGET_VERSION} is online and accepting connections."

# Step 7: Restore Data
log_step "7. Restoring Data into PostgreSQL ${TARGET_VERSION}"
RESTORE_START=$(date +%s)
gunzip -c "${MIGRATION_DUMP}" | docker exec -i -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" psql -U "${PG_USER}" -d postgres -q
RESTORE_END=$(date +%s)
log_success "Data restored successfully in $((RESTORE_END - RESTORE_START))s."

# Step 8: Rebuild Query Planner Statistics
log_step "8. Rebuilding Query Planner Statistics (VACUUM ANALYZE)"
docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" psql -U "${PG_USER}" -d "${PG_DB}" -c "VACUUM ANALYZE;" > /dev/null
log_success "Statistics updated."

# Step 9: Post-Upgrade Schema & Table Verification
log_step "9. Verification & Table Integrity Check"
POST_TABLE_COUNT=$(docker exec -e PGPASSWORD="${PG_PASS}" "${CONTAINER_NAME}" \
    psql -U "${PG_USER}" -d "${PG_DB}" -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null || echo "0")
log_info "Post-upgrade tables:   ${POST_TABLE_COUNT} public tables in '${PG_DB}'"

if [[ "${PRE_TABLE_COUNT}" -gt 0 && "${POST_TABLE_COUNT}" -lt "${PRE_TABLE_COUNT}" ]]; then
    log_error "Table count discrepancy: expected at least ${PRE_TABLE_COUNT}, found ${POST_TABLE_COUNT}."
    exit 1
fi

# Step 10: Restart All Stack Services
log_step "10. Resuming Application Stack"
${COMPOSE_CMD} up -d
log_info "Waiting for WSGI application to start..."
sleep 5

# Test Django connection
if docker ps --format '{{.Names}}' | grep -Fxq "orochi_django_wsgi"; then
    log_info "Testing Django database connectivity..."
    if docker exec orochi_django_wsgi python manage.py showmigrations website &> /dev/null; then
        log_success "Django database connection and schema migrations verified."
    else
        log_warn "Django could not immediately list migrations; check 'docker logs orochi_django_wsgi'."
    fi
fi

# Upgrade succeeded! Disable rollback trap
ROLLBACK_NEEDED=false

echo ""
echo -e "${BOLD}${GREEN}================================================================${NC}"
echo -e "${BOLD}${GREEN}        POSTGRESQL UPGRADE COMPLETED SUCCESSFULLY!${NC}"
echo -e "${BOLD}${GREEN}================================================================${NC}"
echo -e "  ${CYAN}Upgraded from:${NC}       PostgreSQL ${CURRENT_FULL_VER}"
echo -e "  ${CYAN}Upgraded to:${NC}         PostgreSQL ${TARGET_VERSION}"
echo -e "  ${CYAN}Cluster Dump:${NC}        ${MIGRATION_DUMP}"
echo -e "  ${CYAN}Safety Snapshot:${NC}     ${SNAPSHOT_VOLUME}"
echo -e "  ${CYAN}Active Tables:${NC}       ${POST_TABLE_COUNT}"
echo ""
echo -e "  ${YELLOW}Tip:${NC} Keep snapshot volume '${SNAPSHOT_VOLUME}' until you have"
echo -e "       verified your application workflows in production."
echo -e "       To delete the snapshot later: ${BOLD}docker volume rm ${SNAPSHOT_VOLUME}${NC}"
echo -e "${BOLD}${GREEN}================================================================${NC}"
