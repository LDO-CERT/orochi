FROM daskdev/dask:2021.4.0

RUN apt-get update \
    # dependencies for building Python packages
    && apt-get install -y build-essential \
    # django minimal libs 
    libpq-dev gettext \
    # Clamav
    clamav-daemon clamav-freshclam clamav-unofficial-sigs \
    # cleaning up unused files
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && rm -rf /var/lib/apt/lists/*

# Update antivirus and run as a service
COPY ./compose/local/clamav/freshclam.conf /etc/clamav/freshclam.conf
RUN freshclam

# Workers should have similar reqs as django
COPY ./requirements /requirements
RUN pip install -r /requirements/base.txt --ignore-installed ruamel.yaml

COPY ./compose/local/dask/prepare.sh /usr/bin/prepare.sh
RUN chmod +x /usr/bin/prepare.sh

COPY ./compose/local/dask/daskworkerinit.py /opt/daskworkerinit.py

WORKDIR /app
COPY . .
ENV PYTHONPATH "${PYTHONPATH}:/app"
WORKDIR /opt/app

ENTRYPOINT ["tini", "-g", "--", "/usr/bin/prepare.sh"]