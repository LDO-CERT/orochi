FROM python:3.8-slim-buster

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
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

# Requirements are installed here to ensure they will be cached.
COPY ./requirements /requirements
RUN pip install -r /requirements/local.txt

RUN curl -Lo /tmp/windows.zip https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip && \
  unzip /tmp/windows.zip -d /src/volatility/volatility/symbols/ && \
  rm /tmp/windows.zip

RUN curl -Lo /tmp/mac.zip https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip && \
  unzip /tmp/mac.zip -d /src/volatility/volatility/symbols/  && \
  rm /tmp/mac.zip

RUN curl -Lo /tmp/linux.zip https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip && \
  unzip /tmp/linux.zip -d /src/volatility/volatility/symbols/  && \
  rm /tmp/linux.zip

COPY ./compose/production/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint
RUN chmod +x /entrypoint

COPY ./compose/local/django/start /start
RUN sed -i 's/\r$//g' /start
RUN chmod +x /start

WORKDIR /app

ENTRYPOINT ["/entrypoint"]
