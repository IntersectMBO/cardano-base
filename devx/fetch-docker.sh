#!/bin/bash

TOKEN=$(curl --silent https://ghcr.io/token\?scope\=repository:$1:pull | jq -r .token)

BLOB=$(curl \
--silent \
--request 'GET' \
--header "Authorization: Bearer $TOKEN" \
--header "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
--header "Accept: application/vnd.docker.distribution.manifest.v2+json" \
--header "Accept: application/vnd.oci.image.manifest.v1+json" \
"https://ghcr.io/v2/$1/manifests/$2" | tee manifest.json | jq -r '.layers[0].digest')

curl \
--location \
--request GET \
--header "Authorization: Bearer ${TOKEN}" \
"https://ghcr.io/v2/$1/blobs/${BLOB}"
