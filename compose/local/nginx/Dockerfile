# STAGE 1: Generazione certificati SSL
FROM alpine:latest AS alpine

ARG DOMAIN_NAME=orochi.dev
ARG DAYS_VALID=365

RUN apk add --no-cache openssl

RUN echo "Creating self-signed certificate valid for ${DAYS_VALID} days for domain ${DOMAIN_NAME}" && \
    openssl req -x509 \
    -nodes \
    -subj "/CN=${DOMAIN_NAME}" \
    -addext "subjectAltName=DNS:${DOMAIN_NAME}" \
    -days "${DAYS_VALID}" \
    -newkey rsa:2048 -keyout /tmp/self-signed.key \
    -out /tmp/self-signed.crt

# STAGE 2: Build Nginx ModSecurity module dinamico
FROM nginx:latest AS nginx-builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# 1. Installa dipendenze di build
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    curl \
    git \
    libcurl4-openssl-dev \
    libgd-dev \
    libgeoip-dev \
    liblmdb-dev \
    libpcre2-dev \
    libtool \
    libxml2-dev \
    libyajl-dev \
    m4 \
    pkg-config \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Build ModSecurity v3
RUN git clone --depth 1 --recursive -b v3/master https://github.com/owasp-modsecurity/ModSecurity.git /ModSecurity
WORKDIR /ModSecurity
RUN ./build.sh && \
    ./configure --with-pcre2 && \
    make -j"$(nproc)" && \
    make install

# 3. Clone connector ModSecurity-nginx
RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /ModSecurity-nginx

# 4. Scarica sorgenti Nginx ed esegui la build gestendo correttamente i flag con eval
WORKDIR /tmp/nginx-src
RUN NGINX_VERSION=$(nginx -v 2>&1 | cut -d'/' -f2) && \
    curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar -xz --strip-components=1 -C /tmp/nginx-src && \
    CONFARGS=$(nginx -V 2>&1 | sed -n -e 's/configure arguments://p') && \
    mkdir -p /usr/lib/nginx/modules && \
    eval "./configure --with-compat $CONFARGS --add-dynamic-module=/ModSecurity-nginx" && \
    make modules && \
    cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/

# STAGE 3: Immagine NGINX finale
FROM nginx:latest AS nginx

# Installa le sole librerie di runtime necessarie
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4 \
    libgeoip1 \
    liblmdb0 \
    libpcre2-8-0 \
    libxml2 \
    libyajl2 \
    && rm -rf /var/lib/apt/lists/*

# Copia le librerie e il modulo dinamico compilato
COPY --from=nginx-builder /usr/local/modsecurity /usr/local/modsecurity
COPY --from=nginx-builder /usr/local/lib/libmodsecurity.so* /usr/local/lib/
COPY --from=nginx-builder /usr/lib/nginx/modules/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/

# Copia i certificati SSL
COPY --from=alpine /tmp/self-signed.key /etc/ssl/private/
COPY --from=alpine /tmp/self-signed.crt /etc/ssl/certs/

# Aggiorna il linker dinamico
RUN ldconfig

EXPOSE 80 443
STOPSIGNAL SIGTERM
CMD ["nginx", "-g", "daemon off;"]
