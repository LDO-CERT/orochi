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

# Build ModSecurity with nginx
FROM nginx:latest as nginx-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
  git build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev \
  libgd-dev pkg-config && \
  rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity.git /ModSecurity && \
  cd /ModSecurity && \
  git submodule init && git submodule update && \
  ./build.sh && \
  ./configure && \
  make && \
  make install

RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /ModSecurity-nginx

# Prepare an NGINX-based image with ModSecurity and certificate
FROM nginx:latest as nginx
RUN apt-get update && apt-get install -y --no-install-recommends libmodsecurity3 && rm -rf /var/lib/apt/lists/*
COPY --from=nginx-builder /ModSecurity/unicode.mapping /etc/nginx/
COPY --from=nginx-builder /usr/local/modsecurity /usr/local/modsecurity
COPY --from=alpine /tmp/self-signed.key /etc/ssl/private
COPY --from=alpine /tmp/self-signed.crt /etc/ssl/certs
