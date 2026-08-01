# STAGE 1: Generazione certificati SSL
FROM alpine:latest AS alpine
ARG DOMAIN_NAME=orochi.dev
ARG DAYS_VALID=365

RUN apk add --no-cache openssl
RUN echo "Creating self-signed certificate valid for ${DAYS_VALID} days for domain ${DOMAIN_NAME}" && \
    openssl \
    req -x509 \
    -nodes \
    -subj "/CN=${DOMAIN_NAME}" \
    -addext "subjectAltName=DNS:${DOMAIN_NAME}" \
    -days ${DAYS_VALID} \
    -newkey rsa:2048 -keyout /tmp/self-signed.key \
    -out /tmp/self-signed.crt

# STAGE 2: Build Nginx ModSecurity module dinamico su ultima versione
FROM nginx:latest AS nginx-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential libpcre2-dev zlib1g zlib1g-dev libssl-dev \
    libgd-dev pkg-config libtool automake autoconf m4 curl \
    libcurl4-openssl-dev libxml2-dev libyajl-dev libgeoip-dev liblmdb-dev && \
    rm -rf /var/lib/apt/lists/*

# Scarica i sorgenti dell'esatta versione Nginx presente nell'immagine latest
RUN NGINX_VERSION=$(nginx -v 2>&1 | cut -d'/' -f2) && \
    cd /tmp && \
    curl -fsSL https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar xz

# Build ModSecurity v3 con sottomoduli ricorsivi
RUN git clone --depth 1 --recursive -b v3/master https://github.com/owasp-modsecurity/ModSecurity.git /ModSecurity && \
    cd /ModSecurity && \
    ./build.sh && \
    ./configure --with-pcre2 && \
    make -j$(nproc) && \
    make install

# Build ModSecurity-nginx connector
RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /ModSecurity-nginx

# Compila il solo modulo dinamico usando eval per gestire gli apici di CONFARGS
RUN NGINX_VERSION=$(nginx -v 2>&1 | cut -d'/' -f2) && \
    CONFARGS=$(nginx -V 2>&1 | sed -n -e 's/configure arguments://p') && \
    cd /tmp/nginx-${NGINX_VERSION} && \
    eval ./configure --with-compat $CONFARGS --add-dynamic-module=/ModSecurity-nginx && \
    make modules && \
    mkdir -p /usr/lib/nginx/modules && \
    cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/

# STAGE 3: Immagine NGINX finale (latest)
FROM nginx:latest AS nginx

# Installa le librerie di runtime per ModSecurity
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4 \
    libgeoip1 \
    libxml2 \
    libyajl2 \
    liblmdb0 \
    libpcre2-8-0 \
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
