FROM python:3.12.8-slim-bookworm as common-base

ENV DJANGO_SETTINGS_MODULE config.settings.local
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

FROM golang:alpine3.20 as go-builder
RUN apk add git
WORKDIR /
RUN git clone https://github.com/volatilityfoundation/dwarf2json.git
WORKDIR /dwarf2json
RUN /usr/local/go/bin/go build

FROM common-base
WORKDIR /
COPY ./requirements /requirements
RUN pip install uv==0.5.15 -e git+https://github.com/dadokkio/volatility3.git@a98a23fa41395b9bbd961f6e50d0a0f19201fcc7#egg=volatility3 \
  && uv pip install --no-cache --system -r /requirements/base.txt

COPY ./compose/local/__init__.py /src/volatility3/volatility3/framework/constants/__init__.py

#EXPERIMENTAL SUPPORT FOR ARM64
COPY ./compose/local/arm64/pdbscan.py /src/volatility3/volatility3/framework/automagic/pdbscan.py
COPY ./compose/local/arm64/windows.py /src/volatility3/volatility3/framework/automagic/windows.py
COPY ./compose/local/arm64/linux.py /src/volatility3/volatility3/framework/automagic/linux.py
COPY ./compose/local/arm64/arm.py /src/volatility3/volatility3/framework/layers/arm.py
RUN sed -i 's/\["Intel32", "Intel64"\]/\["Intel32", "Intel64", "AArch64"\]/g' /src/volatility3/volatility3/framework/plugins/linux/*.py

RUN mkdir -p $local_folder /maxmind
COPY ./compose/local/maxmind /maxmind

WORKDIR /app
COPY . .
COPY ./compose/local/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint
RUN chmod +x /entrypoint

COPY ./compose/local/django/start /start
RUN sed -i 's/\r$//g' /start
RUN chmod +x /start

COPY --from=go-builder /dwarf2json/dwarf2json /dwarf2json/dwarf2json

WORKDIR /app
ENTRYPOINT ["/entrypoint"]
