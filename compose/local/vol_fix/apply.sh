#!/bin/sh
# Apply Orochi's volatility3 patches (Linux AArch64 support, volatilityfoundation/volatility3#1088).
#
# linux.py is upstream automagic/linux.py merged with the PR, so it is only valid for the
# volatility3 revision pinned in pyproject.toml. When the pin changes, the build stops here:
# re-merge linux.py against the new upstream file (or drop it if #1088 got merged) and
# update UPSTREAM_LINUX_SHA256.
set -eu

SRC=$(dirname "$0")
SP=${SITE_PACKAGES:-$(find /app/.venv/lib -maxdepth 2 -name "site-packages")}
VOL="$SP/volatility3/framework"

# sha256 of automagic/linux.py at volatility3 77ff0b1932d77527f850c8ced01d85805ea7bf97
UPSTREAM_LINUX_SHA256=24587ac72671256c3b224207f140143e401879d728fa92949eac784a1e1ae256

if [ -f "$VOL/layers/arm.py" ]; then
  echo "vol_fix: upstream now ships layers/arm.py, review compose/local/vol_fix before building" >&2
  exit 1
fi
echo "$UPSTREAM_LINUX_SHA256  $VOL/automagic/linux.py" | sha256sum -c - >/dev/null || {
  echo "vol_fix: volatility3 automagic/linux.py changed upstream, re-merge compose/local/vol_fix/linux.py" >&2
  exit 1
}

cp "$SRC/linux.py" "$VOL/automagic/linux.py"
cp "$SRC/arm.py" "$VOL/layers/arm.py"

# 1. Patch constants/architectures.py so plugins referencing LINUX_ARCHS / FRAMEWORK_ARCHS accept AArch64
ARCH_FILE="$VOL/constants/architectures.py"
if [ -f "$ARCH_FILE" ]; then
  python - "$ARCH_FILE" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
src = p.read_text()
orig = src
for old, new in [
    ('["Intel32", "Intel64"]', '["Intel32", "Intel64", "AArch64"]'),
    ("['Intel32', 'Intel64']", "['Intel32', 'Intel64', 'AArch64']"),
    ('("Intel32", "Intel64")', '("Intel32", "Intel64", "AArch64")'),
]:
    src = src.replace(old, new)
if src != orig:
    p.write_text(src)
PY
fi

# 2. Recursively let all Linux plugins (including malware/, tracing/, graphics/) accept AArch64 (excluding x86-only check_idt.py)
PLUGINS=$(find "$VOL/plugins/linux" -type f -name '*.py' ! -name 'check_idt.py' -exec grep -l '\["Intel32", "Intel64"\]' {} + || true)
if [ -n "$PLUGINS" ]; then
  # shellcheck disable=SC2086
  sed -i 's/\["Intel32", "Intel64"\]/["Intel32", "Intel64", "AArch64"]/g' $PLUGINS
fi

# Fail the build if the patched framework does not import
python -c "import volatility3.framework.automagic.linux, volatility3.framework.layers.arm"
