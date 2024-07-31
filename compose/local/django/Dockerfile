# syntax=docker/dockerfile:1.3
ARG TARGETPLATFORM
ARG BUILDPLATFORM

FROM python:3.12-slim-bookworm AS common-base

ENV DJANGO_SETTINGS_MODULE=config.settings.local
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ARG local_folder=/uploads

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential \
  libsasl2-dev python3-dev libldap2-dev libssl-dev \
  libpq-dev libmagic1 p7zip-full gettext git \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app

FROM common-base AS base-builder
RUN apt-get update \
  && apt-get install --no-install-recommends -y curl unzip \
  automake libtool make gcc pkg-config flex bison libssl-dev libjansson-dev libmagic-dev \
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

FROM base-builder AS yara-builder
WORKDIR /tmp
RUN git clone --recursive https://github.com/VirusTotal/yara.git
WORKDIR /tmp/yara
RUN ./bootstrap.sh \
  && ./configure --enable-cuckoo --enable-magic --enable-dotnet --with-crypto \
  && make \
  && make install \
  && echo "Install yara-python..."
WORKDIR /tmp
RUN git clone --branch v4.3.x --recursive https://github.com/VirusTotal/yara-python
WORKDIR /tmp/yara-python
RUN python setup.py build

FROM common-base AS go-builder
ARG TARGETPLATFORM
RUN apt-get update && apt-get install -y curl
RUN echo "Building for platform: $TARGETPLATFORM" \
    && if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
      apt-get install -y gcc-multilib \
      && curl -Lo go.tar.gz https://dl.google.com/go/go1.22.0.linux-amd64.tar.gz \
      && tar -C /usr/local -xzf go.tar.gz \
      && rm go.tar.gz \
      && git clone https://github.com/volatilityfoundation/dwarf2json.git \
      && cd dwarf2json \
      && CC=gcc /usr/local/go/bin/go build; \
    elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
      apt-get install -y gcc-aarch64-linux-gnu \
      && curl -Lo go.tar.gz https://dl.google.com/go/go1.22.0.linux-arm64.tar.gz \
      && tar -C /usr/local -xzf go.tar.gz \
      && rm go.tar.gz \
      && git clone https://github.com/volatilityfoundation/dwarf2json.git \
      && cd dwarf2json \
      && CC=aarch64-linux-gnu-gcc /usr/local/go/bin/go build; \
    else \
      echo "Unsupported platform: $TARGETPLATFORM" && exit 1; \
    fi

FROM common-base
WORKDIR /
COPY ./requirements /requirements
RUN pip install uv==0.1.21 -e git+https://github.com/volatilityfoundation/volatility3.git@55dd39f2ba60ffdd2126b7ea011940f0df42815a#egg=volatility3 \
  && uv pip install --no-cache --system -r /requirements/base.txt

COPY ./compose/local/__init__.py /src/volatility3/volatility3/framework/constants/__init__.py

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

COPY --from=yara-builder /tmp/yara-python/ /tmp/
WORKDIR /tmp
RUN python setup.py install

WORKDIR /app
ENTRYPOINT ["/entrypoint"]
