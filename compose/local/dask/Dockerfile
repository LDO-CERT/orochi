FROM daskdev/dask:2021.7.1

RUN apt-get update \
    # dependencies for building Python packages
    && apt-get install -y build-essential \
    # django minimal libs 
    libpq-dev gettext \
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

RUN cd /tmp/ \
  && git clone --recursive https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && ./configure --enable-cuckoo \
                 --enable-magic \
                 --enable-dotnet \
                 --with-crypto \
  && make \
  && make install \
  && echo "Install yara-python..." \
  && cd /tmp/ \
  && git clone --recursive https://github.com/VirusTotal/yara-python \
  && cd yara-python \
  && python setup.py build \
  && python setup.py install \
  && rm -rf /tmp/*  

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
RUN ldconfig

ENTRYPOINT ["tini", "-g", "--", "/usr/bin/prepare.sh"]