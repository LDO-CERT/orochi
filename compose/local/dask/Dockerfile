FROM continuumio/miniconda3:4.8.2

RUN conda install --yes \
    -c conda-forge \
    python==3.8 \
    python-blosc \
    cytoolz \
    dask==2.24.0 \
    lz4 \
    nomkl \
    numpy==1.19.1 \
    pandas==1.1.1 \
    tini==0.18.0 \
    && conda clean -tipsy \
    && find /opt/conda/ -type f,l -name '*.a' -delete \
    && find /opt/conda/ -type f,l -name '*.pyc' -delete \
    && find /opt/conda/ -type f,l -name '*.js.map' -delete \
    && find /opt/conda/lib/python*/site-packages/bokeh/server/static -type f,l -name '*.js' -not -name '*.min.js' -delete \
    && rm -rf /opt/conda/pkgs

RUN apt-get update \
    # dependencies for building Python packages
    && apt-get install -y build-essential \
    # git for cloning
    && apt-get install -y git curl unzip \
    # psycopg2 dependencies
    && apt-get install -y libpq-dev \
    # Translations dependencies
    && apt-get install -y gettext \
    # Clamav
    && apt-get install -y clamav-daemon clamav-freshclam clamav-unofficial-sigs \
    # cleaning up unused files
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && rm -rf /var/lib/apt/lists/*

COPY ./compose/local/clamav/freshclam.conf /etc/clamav/freshclam.conf
RUN freshclam

RUN mkdir /opt/app
# Requirements are installed here to ensure they will be cached.
COPY ./requirements /requirements
RUN pip install -r /requirements/local.txt

COPY ./compose/local/dask/prepare.sh /usr/bin/prepare.sh
RUN chmod +x /usr/bin/prepare.sh

COPY ./compose/local/dask/daskworkerinit.py /tmp/daskworkerinit.py


WORKDIR /opt/app

ENV PYTHONPATH "${PYTHONPATH}:/app"

ENTRYPOINT ["tini", "-g", "--", "/usr/bin/prepare.sh"]
