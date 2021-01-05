FROM python:3.8.5-slim-buster

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y build-essential \
  # ldap support
  && apt-get install -y libsasl2-dev libldap2-dev libssl-dev \
  # git for cloning
  && apt-get install -y git curl unzip \
  # psycopg2 dependencies
  && apt-get install -y libpq-dev \
  # Translations dependencies
  && apt-get install -y gettext \
  # go for symbols
  && apt-get install -y golang \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

# Requirements are installed here to ensure they will be cached.
COPY ./requirements /requirements
RUN pip install -r /requirements/local.txt

COPY ./compose/local/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint
RUN chmod +x /entrypoint

COPY ./compose/local/django/start /start
RUN sed -i 's/\r$//g' /start
RUN chmod +x /start

WORKDIR /
RUN git clone https://github.com/volatilityfoundation/dwarf2json.git

WORKDIR /dwarf2json
RUN go build && ln -s /src/volatility/development/stock-linux-exitjson.py run.py

WORKDIR /app

ENTRYPOINT ["/entrypoint"]
