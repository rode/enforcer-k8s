#!/usr/bin/env sh

set -euo pipefail

export PATH="/usr/local/Cellar/openssl@1.1/1.1.1i/bin":$PATH

openssl req -nodes -new -x509 -keyout ca.key -out ca.crt -subj "/CN=Rode CA"
openssl genrsa -out webhook.key 4096
openssl req -new -key webhook.key -subj "/CN=enforcer-k8s.default.svc" -addext "subjectAltName = DNS:enforcer-k8s.default.svc" \
    | openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -out webhook-server-tls.crt

# cat ca.crt | base64 | pbcopy