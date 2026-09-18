ARG POSTGRES_VERSION=17.4
FROM postgres:${POSTGRES_VERSION}

COPY ./compose/local/postgres/maintenance /usr/local/bin/maintenance
RUN chmod +x /usr/local/bin/maintenance/*
RUN mv /usr/local/bin/maintenance/* /usr/local/bin \
    && rmdir /usr/local/bin/maintenance
