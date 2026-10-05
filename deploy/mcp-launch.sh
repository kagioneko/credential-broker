#!/bin/bash
# Launch wrapper for the Credential Broker MCP server.
#
# Materialises the connector secret from your secret store into a private tmpfile
# that exists only while this process runs, then starts the stdio server as a
# child (NOT exec) so the EXIT/TERM trap always fires and the tmpfile is deleted
# on shutdown. Configure an MCP client to run this script as the server command.
#
# Adjust the secret-fetch line and the *_ADDR / *_CACERT vars to your setup.
set -euo pipefail

# --- secret store (example: HashiCorp Vault). Set these in the MCP client env. ---
export VAULT_ADDR="${VAULT_ADDR:?set VAULT_ADDR to your Vault address}"
export VAULT_CACERT="${VAULT_CACERT:-}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-secret/credential-broker}"

# Checkout location: explicit env, else this script's parent dir.
ROOT="${CREDENTIAL_BROKER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

umask 077
# Prefer a RAM-backed directory so the secret never reaches persistent disk.
# A trap cannot run on SIGKILL or a hard crash; RAM backing bounds any residue
# to the lifetime of the boot instead of leaving it on disk.
base="${XDG_RUNTIME_DIR:-}"
{ [ -n "$base" ] && [ -d "$base" ] && [ -w "$base" ]; } || base=/dev/shm
{ [ -d "$base" ] && [ -w "$base" ]; } || base="${TMPDIR:-/tmp}"
d="$(mktemp -d "$base/credential-broker.XXXXXX")"
child=""
cleanup() {
  # Delete the secret FIRST: nothing below may block before this runs.
  rm -rf "$d"
  if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
    kill -TERM "$child" 2>/dev/null || true
    # Bounded wait (~5s), then force-kill a child that ignores TERM.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$child" 2>/dev/null || break
      sleep 0.5
    done
    kill -KILL "$child" 2>/dev/null || true
  fi
  [ -n "$child" ] && wait "$child" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Write "KEY=<value>\n" without the value ever hitting argv or stdout.
{ printf 'GITHUB_TOKEN='; vault kv get -field=github_token "$VAULT_SECRET_PATH"; } > "$d/.env"

export DOTENV_PATH="$d/.env"
export CONFIG_PATH="${CONFIG_PATH:-$ROOT/config/credentials.yaml}"
# Optional JSONL audit sink. Per-user, mode 0600 (enforced by the app).
export AUDIT_LOG_PATH="${AUDIT_LOG_PATH:-$HOME/.local/state/credential-broker/audit.jsonl}"
# No BROKER_API_TOKEN: the stdio process boundary is the trust boundary.

cd "$ROOT"
"$ROOT/.venv/bin/python" -m app.mcp_server <&0 &
child=$!
wait "$child"
