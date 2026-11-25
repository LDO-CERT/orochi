ARG TARGETARCH

FROM python:3.15.2-slim-bookworm AS common-base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DJANGO_SETTINGS_MODULE=config.settings.production \
    DEBIAN_FRONTEND=noninteractive \
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
  # WeasyPrint / Pango / GObject / Harfbuzz dependencies
  libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libglib2.0-0 shared-mime-info \
  # git for cloning
  git \
  curl \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/

# App running in /app
RUN mkdir -p /app

FROM golang:alpine3.23 AS go-builder

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

ARG TARGETARCH

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

# Linux AArch64 support for volatility3 (see compose/local/vol_fix/apply.sh)
COPY ./compose/local/vol_fix /tmp/vol_fix
RUN sh /tmp/vol_fix/apply.sh && rm -rf /tmp/vol_fix
RUN mkdir -p "$local_folder" /maxmind /symbols /plugins && \
  SP=$(find /app/.venv/lib -maxdepth 2 -name "site-packages") && \
  rm -rf "$SP/volatility3/symbols" && ln -s /symbols "$SP/volatility3/symbols" && \
  mkdir -p "$SP/volatility3/plugins" && \
  rm -rf "$SP/volatility3/plugins/custom" && ln -s /plugins "$SP/volatility3/plugins/custom"

COPY ./compose/local/maxmind /maxmind
COPY ./compose/local/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint && chmod +x /entrypoint
COPY ./compose/local/django/start /start
RUN sed -i 's/\r$//g' /start && chmod +x /start
COPY --from=go-builder /dwarf2json/dwarf2json /dwarf2json/dwarf2json
COPY --from=rust-builder /btf2json/target/release/btf2json /btf2json/btf2json

WORKDIR /app
ARG TAILWIND_CLI_VERSION=4.3.5
ARG TAILWIND_SHA256_AMD64=e47695cee3f0d90623a91f3939b08bdee610eb5ad99340adff9d4145b284d6cc
ARG TAILWIND_SHA256_ARM64=ffcd0d21dbd7c605dc12743ff0c0b47debc963c86b399674084c1c8f2c96ecad
RUN set -eux; \
  ARCH="$(uname -m)"; \
  case "$ARCH" in \
    x86_64)  TW_ARCH="x64";   TW_SHA="$TAILWIND_SHA256_AMD64" ;; \
    aarch64) TW_ARCH="arm64"; TW_SHA="$TAILWIND_SHA256_ARM64" ;; \
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
  esac; \
  mkdir -p /app/tailwindcss; \
  BIN="/app/tailwindcss/tailwindcss-linux-${TW_ARCH}-${TAILWIND_CLI_VERSION}"; \
  curl -fsSL "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_CLI_VERSION}/tailwindcss-linux-${TW_ARCH}" -o "$BIN"; \
  echo "${TW_SHA}  ${BIN}" | sha256sum -c -; \
  chmod +x "$BIN"

COPY . .

RUN DJANGO_SETTINGS_MODULE=config.settings.test python manage.py tailwind build --skip-checks && \
  DJANGO_SETTINGS_MODULE=config.settings.test python manage.py collectstatic --skip-checks --noinput && \
  touch /app/staticfiles/.collectstatic.stamp && \
  rm -f /tmp/build.db

ENTRYPOINT ["/entrypoint"]
