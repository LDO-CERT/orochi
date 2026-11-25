ARG TARGETARCH

FROM python:3.15.2-slim-bookworm AS common-base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# DISABLE TZDATA INTERACTION
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ARG local_folder=/uploads

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y --no-install-recommends build-essential \
  # ldap
  libsasl2-dev python3-dev libldap2-dev libssl-dev pkg-config \
  # psycopg2 dependencies
  libpq-dev \
  # archive (zstd: unzstd for zstd-compressed .deb/.ddeb kernel debug packages)
  libmagic1 p7zip-full zstd \
  # Translations dependencies
  gettext \
  # Clamav
  clamav-daemon clamav-freshclam clamav-unofficial-sigs \
  # git & curl for cloning and tini download
  git curl \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# App running in /app
RUN mkdir -p /app

FROM golang:alpine3.23 AS go-builder

RUN apk add --no-cache git

WORKDIR /
RUN git clone --depth 1 https://github.com/volatilityfoundation/dwarf2json.git
WORKDIR /dwarf2json
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} \
  /usr/local/go/bin/go build -o dwarf2json .

FROM rust:1-slim-bookworm AS rust-builder

RUN apt-get update \
  && apt-get install -y --no-install-recommends git \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /
RUN git clone --depth 1 https://github.com/vobst/btf2json.git
WORKDIR /btf2json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git \
  cargo build --release --locked

FROM common-base

# uv install requirements
WORKDIR /app/
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
ENV PATH="/app/.venv/bin:$PATH" \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONPATH="/app"
# Dev tools (pytest, debug toolbar, linters) are left out of production images.
# Build with --build-arg INSTALL_DEV=true to run the test suite inside the container.
ARG INSTALL_DEV=false
RUN --mount=type=cache,target=/root/.cache/uv \
  --mount=type=bind,source=uv.lock,target=uv.lock \
  --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
  uv sync --frozen --no-install-project $([ "$INSTALL_DEV" = "true" ] || echo --no-dev)

# STANDARD DASK START SCRIPT
COPY ./compose/local/dask/prepare.sh /usr/bin/prepare.sh
RUN chmod +x /usr/bin/prepare.sh
COPY ./compose/local/dask/daskworkerinit.py /opt/daskworkerinit.py
COPY ./compose/local/clamav/freshclam.conf /etc/clamav/freshclam.conf

# Linux AArch64 support for volatility3 (see compose/local/vol_fix/apply.sh)
COPY ./compose/local/vol_fix /tmp/vol_fix
RUN sh /tmp/vol_fix/apply.sh && rm -rf /tmp/vol_fix
RUN mkdir -p "$local_folder" /maxmind /symbols /plugins && \
  SP=$(find /app/.venv/lib -maxdepth 2 -name "site-packages") && \
  rm -rf "$SP/volatility3/symbols" && ln -s /symbols "$SP/volatility3/symbols" && \
  mkdir -p "$SP/volatility3/plugins" && \
  rm -rf "$SP/volatility3/plugins/custom" && ln -s /plugins "$SP/volatility3/plugins/custom" && \
  ldconfig

ENV TINI_VERSION=v0.19.0
ARG TARGETARCH

RUN set -eux; \
  ARCH="$(dpkg --print-architecture | sed 's/aarch64/arm64/')"; \
  TINI_PLATFORM="tini"; \
  if [ "${TARGETARCH:-amd64}" = "arm64" ]; then \
  TINI_PLATFORM="tini-arm64"; \
  elif [ "${TARGETARCH:-amd64}" = "amd64" ]; then \
  TINI_PLATFORM="tini"; \
  fi; \
  curl -fsSLO "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/${TINI_PLATFORM}"; \
  mv "${TINI_PLATFORM}" /usr/bin/tini; \
  chmod +x /usr/bin/tini

COPY ./compose/local/maxmind /maxmind
COPY --from=go-builder /dwarf2json/dwarf2json /dwarf2json/dwarf2json
COPY --from=rust-builder /btf2json/target/release/btf2json /btf2json/btf2json

WORKDIR /app
COPY . .

ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/usr/bin/prepare.sh"]
