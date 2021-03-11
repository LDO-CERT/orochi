FROM python:3.8.5-slim-buster as common-base

ENV DJANGO_SETTINGS_MODULE config.settings.local
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y build-essential \
  # psycopg2 dependencies
  libpq-dev \
  # Translations dependencies
  gettext 

# App running in /app
RUN mkdir -p /app

FROM common-base as base-builder
RUN apt-get update \
  # ldap support
  && apt-get install -y libsasl2-dev libldap2-dev libssl-dev \
  # git for cloning
  git curl unzip \
  # go for symbols & yaya
  automake libtool make gcc pkg-config\
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

FROM base-builder as go-builder
WORKDIR /

RUN curl https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz --output go1.15.2.linux-amd64.tar.gz \
  && tar -C /usr/local -xzf go1.15.2.linux-amd64.tar.gz

RUN git clone https://github.com/volatilityfoundation/dwarf2json.git
WORKDIR /dwarf2json
RUN /usr/local/go/bin/go build

WORKDIR /yara
RUN apt-get update && apt-get install -y flex bison 
RUN git clone --recursive --branch v4.0.5 https://github.com/VirusTotal/yara.git \
  && cd yara \
  && ./bootstrap.sh \
  && ./configure \
  && make \
  && make install
RUN /usr/local/go/bin/go version
RUN /usr/local/go/bin/go get github.com/EFForg/yaya \
  && cd /root/go/src/github.com/EFForg/yaya \
  && /usr/local/go/bin/go build 

FROM base-builder as builder
WORKDIR /
COPY ./requirements /requirements
RUN pip install -r /requirements/local.txt --no-warn-script-location --prefix=/install

FROM common-base
WORKDIR /app
COPY . .
COPY ./compose/local/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint
RUN chmod +x /entrypoint

COPY ./compose/local/django/start /start
RUN sed -i 's/\r$//g' /start
RUN chmod +x /start

COPY --from=go-builder /dwarf2json/dwarf2json /dwarf2json/dwarf2json
COPY --from=builder /install /usr/local
COPY --from=go-builder /root/go/src/github.com/EFForg/yaya/yaya /yara/yaya 
COPY --from=go-builder /usr/local/lib/libyara.so.4 /usr/local/lib/libyara.so.4 

ENTRYPOINT ["/entrypoint"]
