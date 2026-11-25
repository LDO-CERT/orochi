#!/bin/bash

set -x

# We start by adding extra apt packages, since pip modules may required library
if [ "$EXTRA_APT_PACKAGES" ]; then
    echo "EXTRA_APT_PACKAGES environment variable found.  Installing."
    apt update -y
    apt install -y "$EXTRA_APT_PACKAGES"
fi

if [ "$EXTRA_PIP_PACKAGES" ]; then
    echo "EXTRA_PIP_PACKAGES environment variable found.  Installing."
    pip install "$EXTRA_PIP_PACKAGES"
fi

# Start ClamAV only inside Dask worker containers (not scheduler); keep startup non-blocking.
case " $* " in
    *" worker "*)
        if [ -n "$(find /var/lib/clamav -maxdepth 1 \( -name '*.cvd' -o -name '*.cld' \) -print -quit 2>/dev/null)" ]; then
            service clamav-daemon start || true
            (freshclam --quiet || true) &
        else
            (freshclam --quiet && service clamav-daemon start || true) &
        fi
        ;;
esac
exec "$@"
