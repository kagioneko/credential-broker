#!/bin/bash
# Claude Code PreToolUse(Bash) hook — stop the recurring "token spilled into the
# transcript" incidents. Denies only clear violations; silent-allow otherwise.
#
# Install: reference this from ~/.claude/settings.json
#   "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
#       { "type": "command", "command": "bash <path>/bash-secret-guard.sh" } ] } ] }
#
# stdin: {"tool_name":"Bash","tool_input":{"command":"..."}}

set -euo pipefail

cmd="$(jq -r '.tool_input.command // empty' 2>/dev/null || true)"
[ -n "$cmd" ] || exit 0

deny() {
  jq -cn --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# 1) `vault kv get` without -field  (運用ルール: -field 必須。無指定は全フィールド平文)
if grep -Eq '\bvault[[:space:]]+kv[[:space:]]+get\b' <<<"$cmd" \
   && ! grep -Eq -- '-field[= ]' <<<"$cmd"; then
  deny "運用ルール: 'vault kv get' は -field 指定必須（無指定だと全フィールドが平文出力）。値が要るなら -field=<key> を付けるか、Credential Broker 経由にしてください。"
fi

# 2) a secret literal pasted straight into the command line
if grep -Eq '(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)' <<<"$cmd"; then
  deny "トークン/鍵をコマンドラインにベタ書きしています。Vault(-field 経由) か Credential Broker のハンドルを使ってください（ベタ書きは bash history / トランスクリプトに残ります）。"
fi

# 3) a fetched secret piped into something that prints it
if grep -Eq -- '-field[= ][^|]*\|[[:space:]]*(head|tail|cat|less|more|grep|sed|awk|cut|tr|tee|xxd|od|base64|hexdump|rev|sort|uniq|echo|printf|column)\b' <<<"$cmd"; then
  deny "Vault から取得した値を表示系コマンド(head/cat/grep/sed/echo…)に流しています。伏字にしても漏れます（2026-09-07 の事故）。ファイルへ直接書くか、値を見ずに使ってください。"
fi

exit 0
