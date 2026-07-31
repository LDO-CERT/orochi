FROM alpine:latest as alpine
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

# Build nginx with ModSecurity module
FROM nginx:latest as nginx-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
  git build-essential libpcre2-dev zlib1g zlib1g-dev libssl-dev \
  libgd-dev pkg-config libtool automake autoconf m4 curl && \
  rm -rf /var/lib/apt/lists/*

# Get nginx source version from installed nginx
RUN NGINX_VERSION=$(nginx -v 2>&1 | grep -o '[0-9.]*$') && \
  cd /tmp && \
  curl -fsSL http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar xz

# Build ModSecurity
RUN git clone --recursive https://github.com/SpiderLabs/ModSecurity.git /ModSecurity && \
  cd /ModSecurity && \
  ./build.sh && \
  ./configure && \
  make && \
  make install

# Build ModSecurity-nginx connector
RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /ModSecurity-nginx

# Compile nginx with modsecurity module
RUN cd /tmp/nginx-* && \
  NGINX_CONF=$(nginx -V 2>&1 | grep "configure arguments" | sed 's/^.*configure arguments: //') && \
  ./configure "$NGINX_CONF" --add-dynamic-module=/ModSecurity-nginx && \
  make modules && \
  cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/

# Prepare final NGINX image with ModSecurity
FROM debian:bookworm-slim as nginx
RUN apt-get update && apt-get install -y --no-install-recommends libmodsecurity3 libpcre2-8-0 zlib1g && rm -rf /var/lib/apt/lists/*
COPY --from=nginx-builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=nginx-builder /usr/lib/nginx/modules/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/
COPY --from=nginx-builder /etc/nginx /etc/nginx
COPY --from=nginx-builder /ModSecurity/unicode.mapping /etc/nginx/
COPY --from=nginx-builder /usr/local/modsecurity /usr/local/modsecurity
COPY --from=nginx-builder /var/cache/nginx /var/cache/nginx
COPY --from=nginx-builder /usr/lib/aarch64-linux-gnu/libssl.so.3 /usr/lib/aarch64-linux-gnu/
COPY --from=nginx-builder /usr/lib/aarch64-linux-gnu/libcrypto.so.3 /usr/lib/aarch64-linux-gnu/
COPY --from=alpine /tmp/self-signed.key /etc/ssl/private
COPY --from=alpine /tmp/self-signed.crt /etc/ssl/certs
RUN mkdir -p /var/run/nginx && useradd -r -M -s /sbin/nologin nginx
EXPOSE 80 443
STOPSIGNAL SIGTERM
CMD ["nginx", "-g", "daemon off;"]
