# AI Credential Broker (v0.1)

AI エージェントに API キーを直接渡さず、**期限付き Credential Handle と Capability だけ**
渡す Secret Capability Gateway。実 Secret は Broker だけが扱い、外部 API を代理実行する。

設計書: [`IMPLEMENTATION_DESIGN_v0.1.md`](IMPLEMENTATION_DESIGN_v0.1.md)

## v0.1 スコープ

| | |
|---|---|
| Secret Source | `.env`（tmpfs・secret store 由来）only |
| Connector | GitHub REST v3（read-only） |
| Capability | `github_reader` |
| Actions | `list_repositories` / `get_repository` / `list_issues` / `get_issue` |
| TTL | 300s（max 900s） |
| Store | プロセスメモリ |
| bind | `127.0.0.1:8787` 固定 |

## セットアップ

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

必要な環境変数（本番は systemd EnvironmentFile / tmpfs）:

| 変数 | 説明 |
|------|------|
| `BROKER_API_TOKEN` | エージェント ⇔ Broker の Bearer トークン（未設定なら起動失敗） |
| `CONFIG_PATH` | 既定 `config/credentials.yaml` |
| `DOTENV_PATH` | DotEnvProvider が読む `.env`。既定 `.env` |

## 2つのエントリポイント

コア（`CredentialBroker` / store / policy / providers / actions / sanitizer / audit）は
トランスポート非依存（`app/assembly.py`）。同じ挙動を2通りで公開する。

### A. HTTP（FastAPI）— cron / CPOS / 他ツール向け

```bash
BROKER_API_TOKEN=xxx DOTENV_PATH=.env \
  .venv/bin/uvicorn --factory app.main:create_app --host 127.0.0.1 --port 8787 --workers 1
```

### B. MCP stdio — AI CLI（Claude Code / Codex / Antigravity）向け

AI に見えるのは `list_capabilities` / `request_credential` / `execute` / `revoke` の4ツールだけ。
引数が構造的に `credential_id` / `action` / `parameters` に固定され、**トークンを書く場所が無い**。
stdio のプロセス境界が信頼境界なので bearer トークンは不要。

```bash
python -m app.mcp_server          # 直接
deploy/mcp-launch.sh              # secret store→tmpfile→child のラッパー（MCPクライアントに登録する用）
```

MCP クライアント登録例（`~/.claude/settings.json` の `mcpServers` など環境依存）:

```json
{ "mcpServers": { "credential-broker": {
    "command": "/opt/credential-broker/deploy/mcp-launch.sh"
} } }
```

## API

全エンドポイントで `Authorization: Bearer $BROKER_API_TOKEN` 必須。

| method | path | 用途 |
|--------|------|------|
| GET  | `/capabilities` | 利用可能 credential 一覧（物理 Secret 情報は返さない） |
| POST | `/credentials/request` | `{"credential_id": "..."}` → `{"handle","expires_in"}` |
| POST | `/execute` | `{"credential_handle","action","parameters"}` → `{"status","data"}` |
| POST | `/credentials/revoke` | `{"credential_handle": "..."}` → `{"status":"revoked"}` |

エラーは常に `{"error": "<CODE>"}`:
`UNAUTHORIZED(401)` `RATE_LIMITED(429)` `UNKNOWN_CREDENTIAL(404)` `EXPIRED_HANDLE(410)`
`ACTION_NOT_ALLOWED(403)` `INVALID_PARAMETER(422)` `CREDENTIAL_PROVIDER_ERROR(502)` `PROVIDER_ERROR(502)`

## 異常利用検知 → NekoGuard

Broker は全操作が監査イベントを通るので、そこで疑わしいパターンを閾値判定する（**ブロックはしない・検知のみ**）:

| パターン | 既定閾値 |
|---|---|
| `credential_enumeration` | 未知 credential_id を 5種/60s（同一 client） |
| `denied_action_streak` | 禁止アクション拒否 5回/60s |
| `expired_handle_replay` | 失効ハンドルでの execute 5回/60s |
| `rate_limit_hits` | レート制限拒否 3回/60s |

閾値超過で `anomaly_suspected` イベントを監査ストリームに書き戻す。
`AUDIT_LOG_PATH` を設定すると全監査イベントが JSONL で追記される（ローテート付き）。
NekoGuard 側（`get_recent_broker_anomalies` / `detect_anomalies`）がその JSONL を tail して
`anomaly_suspected` を拾い、`type: credential_broker` のアラートとして Discord 通知する。

NekoGuard `config.json` に `"broker_audit_log": "<path>"` を足すと有効化（未設定なら無効）。
閾値は `config/credentials.yaml` の `anomaly:` ブロックで調整。

## 補助: bash-secret-guard フック

`deploy/hooks/bash-secret-guard.sh` は Claude Code の `PreToolUse(Bash)` フック。
broker がカバーしない任意コマンドでのトークン漏洩を止める（broker と独立して機能）:

- `vault kv get` の `-field` 無し → deny
- トークン/鍵のコマンドラインへのベタ書き → deny
- Vault 取得値を `head`/`cat`/`grep`/`sed`/`echo` 等に流す → deny

`~/.claude/settings.json` の `hooks.PreToolUse` に matcher `Bash` で登録。

## テスト

```bash
.venv/bin/pytest -q                       # 72 tests
.venv/bin/pytest -q --cov=app --cov-report=term-missing
.venv/bin/ruff check .
```

受け入れテスト TEST-001〜008（Secret 非開示 / TTL / Revoke / 未認可 Action / Secret 列挙 /
Path Traversal / Prompt Injection / ログ漏洩）は `tests/` に対応実装あり。

## デプロイ

1. secret store にこの Broker 用の secret を作成し、`github_token`（read-only PAT）と `broker_api_token`（`openssl rand -hex 32`）を入れる
2. `deploy/credential-broker.service` を `/etc/systemd/system/` に配置
3. `systemctl daemon-reload && systemctl enable --now credential-broker`

`ExecStartPre`（`deploy/fetch-secrets.sh`）が secret store → tmpfs `/run/credential-broker/{.env,broker.env}`
を生成し、`ExecStopPost` で削除する。ディスクに Secret を残さない。

## セキュリティ設計の要点

- 未知の `credential_id`（`../../.env` 等含む）は config lookup で `UNKNOWN_CREDENTIAL`
- レスポンスは allowlist 抽出 + トークンパターンマスク + サイズ/件数上限。upstream ヘッダは転送しない
- 期限判定は `time.monotonic()`（NTP 補正の影響を受けない）
- 監査ログは固定フィールドのみ受付（自由文字列を渡せない）。ログ redaction filter を多層防御に併用
- GitHub base URL 固定・リダイレクト追従なし（SSRF 面なし）

## 既知の制限（v0.2 で対応予定）

- 上流レスポンスの 8 MiB キャップは httpx が全体を受信した後の判定。真のストリーミング上限は未実装
- `redact_literals` は 8 文字未満の Secret を対象外にする（GitHub token は 40 字超なので実害なし）
- `SecretRegistry` はスレッド同期なし（単一 event-loop / 1 worker 前提）
- レート制限は client 別でなく全体共通（v0.1 は単一 Broker トークン設計）

詳細な差し込み位置は `IMPLEMENTATION_DESIGN_v0.1.md` §15。
