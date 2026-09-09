#!/bin/bash
# ExecStartPre: materialise secrets from your secret store onto tmpfs
# (systemd RuntimeDirectory). Adjust the fetch commands and *_ADDR / *_CACERT
# to your setup. Example below uses HashiCorp Vault.
#
# Rule: always fetch a single field (never dump a whole secret). Never echo/grep
# the value.
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:?set VAULT_ADDR to your Vault address}"
export VAULT_CACERT="${VAULT_CACERT:-}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-secret/credential-broker}"

umask 077
d=/run/credential-broker
mkdir -p "$d"

# Write "KEY=<value>\n" without the value ever hitting argv or stdout.
{ printf 'GITHUB_TOKEN='; vault kv get -field=github_token "$VAULT_SECRET_PATH"; } > "$d/.env"
chmod 600 "$d/.env"

{ printf 'BROKER_API_TOKEN='; vault kv get -field=broker_api_token "$VAULT_SECRET_PATH"; } > "$d/broker.env"
chmod 600 "$d/broker.env"
