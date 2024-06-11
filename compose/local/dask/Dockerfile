FROM daskdev/dask:2024.5.2-py3.12
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
RUN git clone --branch v4.3.x --recursive https://github.com/VirusTotal/yara-python
WORKDIR /tmp/yara-python
RUN python setup.py build \
  && python setup.py install \
  && rm -rf /tmp/*

# Workers should have similar reqs as django
WORKDIR /
COPY ./requirements /requirements
RUN pip install uv==0.2.10 -e git+https://github.com/volatilityfoundation/volatility3.git@543a39485bdf57df47d731b55ab112e04f3033f0#egg=volatility3 \
  && uv pip install --no-cache --system -r /requirements/base.txt

COPY ./compose/local/dask/prepare.sh /usr/bin/prepare.sh
RUN chmod +x /usr/bin/prepare.sh

COPY ./compose/local/dask/daskworkerinit.py /opt/daskworkerinit.py
COPY ./compose/local/__init__.py /src/volatility3/volatility3/framework/constants/__init__.py

#EXPERIMENTAL SUPPORT FOR ARM64
COPY ./compose/local/linux.py /src/volatility3/volatility3/framework/automagic/linux.py
COPY ./compose/local/arm.py /src/volatility3/volatility3/framework/layers/arm.py
RUN sed -i 's/\["Intel32", "Intel64"\]/\["Intel32", "Intel64", "AArch64"\]/g' /src/volatility3/volatility3/framework/plugins/linux/*.py

RUN mkdir -p $local_folder /maxmind
COPY ./compose/local/maxmind /maxmind

WORKDIR /app
COPY . .
ENV PYTHONPATH "${PYTHONPATH}:/app"
WORKDIR /opt/app
RUN ldconfig

ENTRYPOINT ["tini", "-g", "--", "/usr/bin/prepare.sh"]
