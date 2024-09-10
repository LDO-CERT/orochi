FROM daskdev/dask:2024.8.2-py3.12
ENV DEBIAN_FRONTEND noninteractive

ARG local_folder=/uploads

RUN apt-get --allow-releaseinfo-change update \
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
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

# Update antivirus and run as a service
COPY ./compose/local/clamav/freshclam.conf /etc/clamav/freshclam.conf
RUN freshclam

# Workers should have similar reqs as django
WORKDIR /
COPY ./requirements /requirements
RUN pip install uv==0.4.2 -e git+https://github.com/dadokkio/volatility3.git@d56cd83510e64f9f875ff1dad11d8c8cbf5995f5#egg=volatility3 \
  && uv pip install --no-cache --system -r /requirements/base.txt

COPY ./compose/local/dask/prepare.sh /usr/bin/prepare.sh
RUN chmod +x /usr/bin/prepare.sh

COPY ./compose/local/dask/daskworkerinit.py /opt/daskworkerinit.py
COPY ./compose/local/__init__.py /src/volatility3/volatility3/framework/constants/__init__.py

#EXPERIMENTAL SUPPORT FOR ARM64
COPY ./compose/local/arm64/pdbscan.py /src/volatility3/volatility3/framework/automagic/pdbscan.py
COPY ./compose/local/arm64/windows.py /src/volatility3/volatility3/framework/automagic/windows.py
COPY ./compose/local/arm64/arm.py /src/volatility3/volatility3/framework/layers/arm.py
RUN sed -i 's/\["Intel32", "Intel64"\]/\["Intel32", "Intel64", "AArch64"\]/g' /src/volatility3/volatility3/framework/plugins/linux/*.py

RUN mkdir -p $local_folder /maxmind
COPY ./compose/local/maxmind /maxmind

WORKDIR /app
COPY . .
ENV PYTHONPATH "${PYTHONPATH}:/app"
WORKDIR /opt/app
RUN ldconfig

ENTRYPOINT ["tini", "-g", "--", "/usr/bin/prepare.sh"]
