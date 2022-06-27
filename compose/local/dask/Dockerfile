FROM daskdev/dask:2022.6.1-py3.9
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get --allow-releaseinfo-change update \
  # dependencies for building Python packages
  && apt-get install --no-install-recommends -y build-essential \
  # django minimal libs
  libpq-dev gettext \
  # zip
  libmagic1 p7zip-full \
  # Clamav
  clamav-daemon clamav-freshclam clamav-unofficial-sigs \
  # requirement to compile yara
  automake libtool make gcc pkg-config flex bison libssl-dev libjansson-dev libmagic-dev \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

# Update antivirus and run as a service
COPY ./compose/local/clamav/freshclam.conf /etc/clamav/freshclam.conf
RUN freshclam

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
RUN python setup.py build \
  && python setup.py install \
  && rm -rf /tmp/*

# Workers should have similar reqs as django
WORKDIR /
COPY ./requirements /requirements
RUN pip install -r /requirements/base.txt --ignore-installed ruamel.yaml

COPY ./compose/local/dask/prepare.sh /usr/bin/prepare.sh
RUN chmod +x /usr/bin/prepare.sh

COPY ./compose/local/dask/daskworkerinit.py /opt/daskworkerinit.py

WORKDIR /app
COPY . .
ENV PYTHONPATH "${PYTHONPATH}:/app"
WORKDIR /opt/app
RUN ldconfig

ENTRYPOINT ["tini", "-g", "--", "/usr/bin/prepare.sh"]
