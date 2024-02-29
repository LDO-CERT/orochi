FROM python:3.12-slim-bookworm as common-base

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
  # git from yara cloning
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
  # requirement to compile yara
  automake libtool make gcc pkg-config flex bison libssl-dev libjansson-dev libmagic-dev \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

# Build yara and yara-python from sources
FROM base-builder as yara-builder
WORKDIR /tmp
RUN git clone --recursive https://github.com/VirusTotal/yara.git
WORKDIR /tmp/yara
RUN ./bootstrap.sh \
  && ./configure --enable-cuckoo \
  --enable-magic \
  --enable-dotnet \
  --with-crypto \
  && make \
  && make install \
  && echo "Install yara-python..."
WORKDIR /tmp
RUN git clone --branch v4.3.x --recursive https://github.com/VirusTotal/yara-python
WORKDIR /tmp/yara-python
RUN python setup.py build

FROM base-builder as go-builder
WORKDIR /
RUN curl https://dl.google.com/go/go1.22.0.linux-amd64.tar.gz --output go1.22.0.linux-amd64.tar.gz \
  && tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
RUN git clone https://github.com/volatilityfoundation/dwarf2json.git
WORKDIR /dwarf2json
RUN /usr/local/go/bin/go build

FROM common-base
WORKDIR /
COPY ./requirements /requirements
RUN pip install uv==0.1.12 && uv pip install --no-cache --system -r /requirements/base.txt

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
# Install yara-python
COPY --from=yara-builder  /tmp/yara-python/ /tmp/
WORKDIR /tmp
RUN python setup.py install

WORKDIR /app
ENTRYPOINT ["/entrypoint"]
