ARG TARGETARCH

FROM python:3.15.2-slim-bookworm as common-base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DJANGO_SETTINGS_MODULE config.settings.local
# DISABLE TZDATA INTERACTION
ENV DEBIAN_FRONTEND noninteractive
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

ARG local_folder=/uploads

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y --no-install-recommends build-essential \
  # ldap
  libsasl2-dev python3-dev libldap2-dev libssl-dev pkg-config \
  # psycopg2 dependencies
  libpq-dev \
  # archive
  libmagic1 p7zip-full \
  # Translations dependencies
  gettext \
  # Clamav
  clamav-daemon clamav-freshclam clamav-unofficial-sigs \
  # WeasyPrint / Pango / GObject / Harfbuzz dependencies
  libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libglib2.0-0 shared-mime-info \
  # git for cloning
  git \
  curl unzip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/

# Install Rust and Cargo for building Rust-based Python packages
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
  && export PATH="/root/.cargo/bin:$PATH"

# App running in /app
RUN mkdir -p /app

FROM common-base as base-builder
RUN apt-get update \
  && apt-get install --no-install-recommends -y \
  # utils
  curl unzip \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

# Update antivirus and run as a service
COPY ./compose/local/clamav/freshclam.conf /etc/clamav/freshclam.conf
RUN freshclam

FROM golang:alpine3.23 as go-builder

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

ARG TARGETARCH

RUN apk add --no-cache git

WORKDIR /
RUN git clone https://github.com/volatilityfoundation/dwarf2json.git
WORKDIR /dwarf2json
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} \
  /usr/local/go/bin/go build -o dwarf2json .

FROM common-base

# uv install requirements
WORKDIR /app/
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
ENV PATH="/app/.venv/bin:$PATH"
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
RUN --mount=type=cache,target=/root/.cache/uv \
  --mount=type=bind,source=uv.lock,target=uv.lock \
  --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
  uv sync --frozen --no-install-project

ENV PYTHONPATH "${PYTHONPATH}:/app"

RUN mkdir -p "$local_folder" /maxmind
COPY ./compose/local/maxmind /maxmind

WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/root/.cache/uv uv sync

#EXPERIMENTAL SUPPORT FOR ARM64 & REMOTE_ISF_URL
COPY ./compose/local/vol_fix/__init__constants.py /tmp/vol_fix/__init__constants.py
COPY ./compose/local/vol_fix/linux.py /tmp/vol_fix/linux.py
COPY ./compose/local/vol_fix/arm.py /tmp/vol_fix/arm.py
RUN mkdir -p /symbols /plugins && \
  SP=$(find /app/.venv/lib -maxdepth 2 -name "site-packages") && \
  cp /tmp/vol_fix/__init__constants.py "$SP/volatility3/framework/constants/__init__.py" && \
  cp /tmp/vol_fix/linux.py "$SP/volatility3/framework/automagic/linux.py" && \
  cp /tmp/vol_fix/arm.py "$SP/volatility3/framework/layers/arm.py" && \
  sed -i 's/\["Intel32", "Intel64"\]/\["Intel32", "Intel64", "AArch64"\]/g' "$SP"/volatility3/framework/plugins/linux/*.py && \
  rm -rf /tmp/vol_fix && \
  rm -rf "$SP/volatility3/symbols" && ln -s /symbols "$SP/volatility3/symbols" && \
  mkdir -p "$SP/volatility3/plugins" && \
  rm -rf "$SP/volatility3/plugins/custom" && ln -s /plugins "$SP/volatility3/plugins/custom"


COPY ./compose/local/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint && chmod +x /entrypoint

COPY ./compose/local/django/start /start
RUN sed -i 's/\r$//g' /start && chmod +x /start

COPY --from=go-builder /dwarf2json/dwarf2json /dwarf2json/dwarf2json

ENTRYPOINT ["/entrypoint"]
