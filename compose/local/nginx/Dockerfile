ARG TARGETARCH

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

# Prepare an NGINX-based image with the certificate created above.
FROM nginx:latest as nginx
COPY --from=alpine /tmp/self-signed.key /etc/ssl/private
COPY --from=alpine /tmp/self-signed.crt /etc/ssl/certs
