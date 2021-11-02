FROM python:3.9.0-slim-buster as common-base

ENV DJANGO_SETTINGS_MODULE config.settings.local
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y --no-install-recommends build-essential \
  # psycopg2 dependencies
  libpq-dev \
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
  # ldap support
  && apt-get install --no-install-recommends -y libsasl2-dev libldap2-dev libssl-dev \
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
RUN git clone --recursive https://github.com/VirusTotal/yara-python 
WORKDIR /tmp/yara-python 
RUN python setup.py build

FROM base-builder as go-builder
WORKDIR /
RUN curl https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz --output go1.15.2.linux-amd64.tar.gz \
  && tar -C /usr/local -xzf go1.15.2.linux-amd64.tar.gz
RUN curl https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz --output go1.15.2.linux-amd64.tar.gz \
  && tar -C /usr/local -xzf go1.15.2.linux-amd64.tar.gz
RUN git clone https://github.com/volatilityfoundation/dwarf2json.git
WORKDIR /dwarf2json
RUN /usr/local/go/bin/go build

FROM common-base
WORKDIR /
COPY ./requirements /requirements
RUN pip install -r /requirements/local.txt --ignore-installed ruamel.yaml

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
