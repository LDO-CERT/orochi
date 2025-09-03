FROM python:3.13.6-slim-bookworm as common-base


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
  libsasl2-dev python3-dev libldap2-dev libssl-dev \
  # psycopg2 dependencies
  libpq-dev \
  # archive
  libmagic1 p7zip-full \
  # Translations dependencies
  gettext \
  # Clamav
  clamav-daemon clamav-freshclam clamav-unofficial-sigs \
  # git for cloning
  git \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

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

FROM golang:alpine3.20 as go-builder
RUN apk add --no-cache git
WORKDIR /
RUN git clone https://github.com/volatilityfoundation/dwarf2json.git
WORKDIR /dwarf2json
RUN /usr/local/go/bin/go build

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

RUN mkdir -p $local_folder /maxmind
COPY ./compose/local/maxmind /maxmind

WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/root/.cache/uv uv sync

#EXPERIMENTAL SUPPORT FOR ARM64 & REMOTE_ISF_URL
COPY ./compose/local/vol_fix/__init__constants.py /app/.venv/lib/python3.13/site-packages/volatility3/framework/constants/__init__.py
COPY ./compose/local/vol_fix/linux.py /app/.venv/lib/python3.13/site-packages/volatility3/framework/automagic/linux.py
COPY ./compose/local/vol_fix/arm.py /app/.venv/lib/python3.13/site-packages/volatility3/framework/layers/arm.py
COPY ./compose/local/vol_fix/__init__symbols.py /app/.venv/lib/python3.13/site-packages/volatility3/symbols/__init__.py
RUN sed -i 's/\["Intel32", "Intel64"\]/\["Intel32", "Intel64", "AArch64"\]/g' /app/.venv/lib/python3.13/site-packages/volatility3/framework/plugins/linux/*.py && \
  pip install --force-reinstall --no-cache-dir python-ldap==3.4.4


COPY ./compose/local/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint && chmod +x /entrypoint

COPY ./compose/local/django/start /start
RUN sed -i 's/\r$//g' /start && chmod +x /start

COPY --from=go-builder /dwarf2json/dwarf2json /dwarf2json/dwarf2json

ENTRYPOINT ["/entrypoint"]
