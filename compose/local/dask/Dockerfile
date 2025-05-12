FROM python:3.13.2-slim-bookworm as common-base

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
RUN apk add git
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

# STANDARD DASK START SCRIPT
COPY ./compose/local/dask/prepare.sh /usr/bin/prepare.sh
RUN chmod +x /usr/bin/prepare.sh
COPY ./compose/local/dask/daskworkerinit.py /opt/daskworkerinit.py

RUN mkdir -p $local_folder /maxmind
COPY ./compose/local/maxmind /maxmind

WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/root/.cache/uv uv sync

#EXPERIMENTAL SUPPORT FOR ARM64 & REMOTE_ISF_URL
COPY ./compose/local/__init__.py /app/.venv/lib/python3.13/site-packages/volatility3/framework/constants/__init__.py
COPY ./compose/local/arm64/linux.py /app/.venv/lib/python3.13/site-packages/volatility3/framework/automagic/linux.py
COPY ./compose/local/arm64/arm.py /app/.venv/lib/python3.13/site-packages/volatility3/framework/layers/arm.py
RUN sed -i 's/\["Intel32", "Intel64"\]/\["Intel32", "Intel64", "AArch64"\]/g' /app/.venv/lib/python3.13/site-packages/volatility3/framework/plugins/linux/*.py

RUN pip install --force-reinstall python-ldap

RUN ldconfig

# Tini
ADD https://github.com/krallin/tini/releases/download/v0.19.0/tini /tini
RUN chmod +x /tini

COPY --from=go-builder /dwarf2json/dwarf2json /dwarf2json/dwarf2json

ENTRYPOINT ["/tini", "-g", "--", "/usr/bin/prepare.sh"]
