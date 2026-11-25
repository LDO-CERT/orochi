"""Regression tests for Issue #1575: Postgres upgrade rollback safety and --compose-file handling."""

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
UPGRADE_SCRIPT = ROOT / "scripts" / "postgres" / "upgrade_postgres.sh"


def _make_fake_docker(bin_dir: Path, state_dir: Path, fail_snapshot: bool = False) -> Path:
    """Create a mock `docker` executable that records invocations and simulates volumes/containers."""
    docker_bin = bin_dir / "docker"
    log_file = state_dir / "docker.log"
    fail_flag = "1" if fail_snapshot else "0"
    script = f"""#!/usr/bin/env bash
set -e
echo "docker $*" >> "{log_file}"
case "$1" in
  compose)
    if [[ "$2" == "version" ]]; then
      echo "Docker Compose version v2.29.0"
      exit 0
    fi
    exit 0
    ;;
  ps)
    echo "orochi_postgres"
    exit 0
    ;;
  exec)
    if [[ "$*" == *"SHOW server_version"* ]]; then
      echo "16.2"
    elif [[ "$*" == *"printenv POSTGRES_USER"* ]]; then
      echo "debug"
    elif [[ "$*" == *"printenv POSTGRES_PASSWORD"* ]]; then
      echo "debug"
    elif [[ "$*" == *"printenv POSTGRES_DB"* ]]; then
      echo "orochi"
    elif [[ "$*" == *"information_schema.tables"* ]]; then
      echo "42"
    elif [[ "$*" == *"pg_dumpall"* ]]; then
      echo "-- mock sql dump"
    elif [[ "$*" == *"pg_isready"* ]]; then
      exit 0
    fi
    exit 0
    ;;
  inspect)
    if [[ "$*" == *"Config.Image"* ]]; then
      echo "postgres:16.2"
    else
      echo "live_pg_vol"
    fi
    exit 0
    ;;
  pull)
    exit 0
    ;;
  stop|rm)
    exit 0
    ;;
  volume)
    sub="$2"
    vname="$3"
    if [[ "$sub" == "create" ]]; then
      mkdir -p "{state_dir}/vol_$vname"
      echo "$vname"
    elif [[ "$sub" == "inspect" ]]; then
      [[ -d "{state_dir}/vol_$vname" ]]
    elif [[ "$sub" == "rm" ]]; then
      rm -rf "{state_dir}/vol_$vname"
    fi
    exit 0
    ;;
  run)
    if [[ "$*" == *"cp -a /from/. /to/"* ]]; then
      if [[ "{fail_flag}" == "1" ]]; then
        echo "Error response from daemon: pull access denied for alpine" >&2
        exit 1
      fi
      # Simulate copying PG_VERSION into snapshot volume
      for arg in "$@"; do
        if [[ "$arg" == *":/to" ]]; then
          snap="${{arg%%:/to}}"
          mkdir -p "{state_dir}/vol_$snap"
          echo "16" > "{state_dir}/vol_$snap/PG_VERSION"
        fi
      done
      exit 0
    elif [[ "$*" == *"test -s /check/PG_VERSION"* ]]; then
      for arg in "$@"; do
        if [[ "$arg" == *":/check:ro" ]]; then
          snap="${{arg%%:/check:ro}}"
          test -s "{state_dir}/vol_$snap/PG_VERSION"
          exit $?
        fi
      done
    fi
    exit 0
    ;;
esac
exit 0
"""
    docker_bin.write_text(script, encoding="utf-8")
    docker_bin.chmod(docker_bin.stat().st_mode | stat.S_IEXEC)
    return log_file


def test_failed_snapshot_preserves_live_volume_and_honours_compose_file(tmp_path):
    """AC1-AC3 (#1575): Forced snapshot failure must NOT delete/overwrite live volume and must use --compose-file."""
    bin_dir = tmp_path / "bin"
    state_dir = tmp_path / "state"
    bin_dir.mkdir()
    state_dir.mkdir()
    live_vol = state_dir / "vol_live_pg_vol"
    live_vol.mkdir()
    sentinel = live_vol / "sentinel_row.txt"
    sentinel.write_text("precious_data_row", encoding="utf-8")

    log_file = _make_fake_docker(bin_dir, state_dir, fail_snapshot=True)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    proc = subprocess.run(
        [
            "bash",
            str(UPGRADE_SCRIPT),
            "--to",
            "17.4",
            "--compose-file",
            "custom-compose.yml",
            "--backup-dir",
            str(tmp_path / "backups"),
            "--no-prompt",
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode != 0, "Failed upgrade must exit non-zero"
    # Live data volume and its sentinel row MUST survive untouched
    assert sentinel.exists()
    assert sentinel.read_text(encoding="utf-8") == "precious_data_row"

    calls = log_file.read_text(encoding="utf-8")
    assert "docker volume rm live_pg_vol\n" not in calls
    # DB must be stopped before snapshot copy
    stop_pos = calls.find("docker stop orochi_postgres")
    cp_pos = calls.find("cp -a /from/. /to/")
    assert stop_pos != -1 and cp_pos != -1 and stop_pos < cp_pos
    # --compose-file must be passed to docker compose
    assert "docker compose -f custom-compose.yml up -d postgres" in calls


def test_happy_path_honours_compose_file_and_validates_snapshot(tmp_path):
    """Happy-path test (#1575): snapshot is validated and --compose-file is used for all compose calls."""
    bin_dir = tmp_path / "bin"
    state_dir = tmp_path / "state"
    bin_dir.mkdir()
    state_dir.mkdir()
    (state_dir / "vol_live_pg_vol").mkdir()

    log_file = _make_fake_docker(bin_dir, state_dir, fail_snapshot=False)
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    proc = subprocess.run(
        [
            "bash",
            str(UPGRADE_SCRIPT),
            "--to",
            "17.4",
            "--compose-file",
            "prod-compose.yml",
            "--backup-dir",
            str(tmp_path / "backups"),
            "--no-prompt",
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    calls = log_file.read_text(encoding="utf-8")
    assert "test -s /check/PG_VERSION" in calls
    assert "docker compose -f prod-compose.yml up -d postgres" in calls
    assert "docker compose -f prod-compose.yml up -d\n" in calls
