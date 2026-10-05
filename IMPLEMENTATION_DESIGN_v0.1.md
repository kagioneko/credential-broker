# AI Credential Broker — 実装設計書 v0.1（実装投入用）

対象仕様: 「AI Credential Broker 実装仕様書 v0.1」
本書の位置づけ: 仕様書を **そのまま Claude Code / Codex に投げて実装できる粒度** に落としたもの。
関数シグネチャ・設定スキーマ・エラーコード・テストケース対応まで確定させる。

---

## 0. スコープ確定（v0.1 で「作るもの / 作らないもの」）

### 作るもの（これだけ）

| 項目 | 確定値 |
|------|--------|
| Secret Source | `DotEnvProvider` のみ（1個） |
| Broker 実装 | Python 3.11+ / FastAPI / uvicorn |
| Temporary Store | プロセスメモリ（dict） |
| TTL | default 300s / max 900s |
| API Connector | GitHub REST v3 のみ |
| Capability | `github_reader` のみ |
| Actions | `list_repositories` / `get_repository` / `list_issues` / `get_issue`（全て read） |
| Broker 自身の認証 | 静的 Bearer トークン（**仕様への推奨追加。§2 参照**） |
| bind | `127.0.0.1:8787` 固定 |

### 作らないもの（v0.1 では実装しない）

- Write 系 GitHub Action（`create_*` / `update_*` / `delete_*`）
- Vault / Environment / クラウド Secret Manager Provider（インターフェースだけ用意、実装は v0.2）
- 元 API キーのローテーション・失効・自動生成
- 永続 Audit DB（v0.1 は構造化ログのみ）
- マルチテナント / Per-Agent Policy / Human Approval フロー
- NekoGuard 連携の実送信（イベント形状だけ確定、送信は v0.2）

---

## 1. 技術スタックとバージョン

`requirements.txt`（例・2026-01 時点の安定版。実装時に最新パッチへ寄せる）

```
fastapi==0.115.*
uvicorn[standard]==0.34.*
pydantic==2.10.*
pydantic-settings==2.7.*
httpx==0.28.*
python-dotenv==1.0.1
PyYAML==6.0.2
```

`requirements-dev.txt`

```
pytest==8.3.*
pytest-asyncio==0.24.*
respx==0.22.*          # httpx のモック（api.github.com を差し替え）
anyio==4.*
ruff==0.8.*
```

- **`.venv` 推奨**（グローバルインストールしない）。
- 非同期前提。すべての I/O（GitHub 呼び出し）は `httpx.AsyncClient`。

---

## 2. 仕様への推奨追加（4点）— v0.1 に入れるべき

仕様書は Broker 自体のアクセス制御に触れていないが、Broker は**全 Secret を保持し外部 API を代理実行する最重要資産**なので、以下を v0.1 の必須要件に格上げする。

### 2.1 Broker API 認証（必須）

- 全エンドポイント（`/capabilities` 含む）で `Authorization: Bearer <BROKER_API_TOKEN>` を要求。
- トークンは起動時に環境変数 `BROKER_API_TOKEN` から読み込み、`secrets.compare_digest` で定数時間比較。
- 未設定なら**起動失敗**（fail-closed）。
- このトークンは「AI エージェント ⇔ Broker」間の唯一の認証情報。Broker が扱う Secret とは別レイヤ。
- 401 時のレスポンスボディは `{"error": "UNAUTHORIZED"}` のみ（理由の詳細を返さない）。

### 2.2 bind は 127.0.0.1 固定 / 環境変数で 0.0.0.0 にできない

- uvicorn 起動を `--host 127.0.0.1` にハードコード。設定で公開 bind に変更する経路を作らない。
- リモートのエージェントから使う場合も localhost forward（SSH トンネル等）を前提にする。

### 2.3 最小レート制限（cheap・enumeration 抑止 & NekoGuard シグナル源）

- プロセス内スライディングウィンドウ。
  - `POST /credentials/request`: 既定 20 回 / 60s
  - `POST /execute`: 既定 60 回 / 60s
- 超過時 `429 {"error": "RATE_LIMITED"}`。
- 設定 `rate_limit.request_per_min` / `rate_limit.execute_per_min` で調整可（0 で無効化可）。

### 2.4 Secret ゼロ化の限界を明記（実装ノート）

- Python の `str` は不変でメモリ上のゼロ化ができない。「TTL 満了で破棄」は**参照の削除（`del` + dict pop）**であって物理ゼロ化ではない。
- 緩和策として v0.1 では:
  - Secret を Broker 内で保持する箇所を **`CredentialStore` の 1 箇所だけ**にする。
  - Secret 文字列を他の変数へコピーしない・ログ/例外/レスポンスに乗せない（§9）。
  - `httpx` に渡す `Authorization` ヘッダは実行直前に組み立て、実行後にローカル変数を `del`。
- 物理ゼロ化が要件化したら v0.4 で `bytearray` ベースの SecretBox を導入（設計拡張ポイント §15）。

### 2.5 【運用】.env は secret store 由来にする

- `.env` に実値をハードコードしない方針なら、`DotEnvProvider` が読む `.env` は**起動時に secret store から生成した tmpfs 上のファイル**にする（§13 参照）。
- `DotEnvProvider` は「ファイルパスを与えられて読むだけ」の実装にして、その出所（secret store）は起動側の責務にする＝仕様書のインターフェースは変えない。

---

## 3. ディレクトリ構成（確定）

```
credential-broker/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app 生成 / lifespan / ルーター登録
│   ├── settings.py          # BrokerSettings（環境変数: BROKER_API_TOKEN, CONFIG_PATH, ...）
│   ├── deps.py              # 認証依存性 require_broker_token, get_broker
│   ├── errors.py            # BrokerError 階層 + FastAPI exception handler
│   │
│   ├── broker.py            # CredentialBroker（オーケストレータ）
│   ├── policy.py            # PolicyEngine
│   ├── store.py             # CredentialStore（in-memory + TTL）
│   ├── cleanup.py           # CleanupWorker（asyncio background task）
│   ├── ratelimit.py         # SlidingWindowLimiter
│   ├── config_loader.py     # credentials.yaml のロード + バリデーション
│   │
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── base.py          # SecretProvider(ABC)
│   │   ├── dotenv.py        # DotEnvProvider
│   │   ├── environment.py   # EnvironmentProvider（v0.2・雛形のみ）
│   │   └── vault.py         # VaultProvider（v0.2・雛形のみ）
│   │
│   ├── actions/
│   │   ├── __init__.py
│   │   ├── base.py          # ActionExecutor(ABC), ActionSpec, ActionResult
│   │   ├── registry.py      # connector 名 -> Executor の解決
│   │   └── github.py        # GitHubReadExecutor + 4 アクション定義
│   │
│   ├── security/
│   │   ├── __init__.py
│   │   ├── sanitizer.py     # レスポンス sanitize（allowlist 抽出）
│   │   ├── validation.py    # パラメータ検証（pydantic モデル per action）
│   │   ├── redaction.py     # ログ redaction filter + SecretRegistry
│   │   └── audit.py         # AuditLogger（構造化ログ出力）
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── api.py           # リクエスト/レスポンス Pydantic モデル
│   │   ├── config.py        # CredentialConfig, BrokerConfig（YAML マッピング）
│   │   └── credential.py    # TemporaryCredential（内部）
│   │
│   └── api/
│       ├── __init__.py
│       └── routes.py        # 全エンドポイント
│
├── config/
│   └── credentials.yaml     # Credential Mapping + Policy（§5）
│
├── tests/
│   ├── conftest.py
│   ├── test_capabilities.py
│   ├── test_broker.py       # TEST-001, TEST-003
│   ├── test_ttl.py          # TEST-002
│   ├── test_policy.py       # TEST-004
│   ├── test_provider.py
│   ├── test_injection.py    # TEST-005, TEST-006, TEST-007
│   ├── test_logging.py      # TEST-008
│   └── test_actions_github.py
│
├── deploy/
│   ├── credential-broker.service     # systemd unit（§13）
│   └── fetch-secrets.sh              # Vault -> tmpfs .env（ExecStartPre）
│
├── .env.example
├── .gitignore               # .env / .venv / __pycache__ / *.log / config/*.local.yaml
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml           # ruff / pytest 設定
└── README.md
```

`.gitignore` は**セキュリティ hook 対応で最初のコミットに必ず含める**（`.env`, `.claude/`, `.venv`, `*.log`）。

---

## 4. データモデル（Pydantic v2・確定フィールド）

### 4.1 内部モデル `app/models/credential.py`

```python
from dataclasses import dataclass, field

@dataclass
class TemporaryCredential:
    handle: str                 # "cred_" + token_urlsafe(24)
    credential_id: str          # "github_reader"
    connector: str              # "github"
    secret: str                 # 実 Secret Value（このオブジェクト以外に保持しない）
    allowed_actions: tuple[str, ...]
    created_at: float           # time.time()  … 監査表示用（wall clock）
    expires_at_mono: float      # time.monotonic() + ttl … 期限判定はこちらのみ使用
    client_id: str              # 認証済みクライアント識別（v0.1 は固定 "agent"）

    def remaining(self, now_mono: float) -> int:
        return max(0, int(self.expires_at_mono - now_mono))

    def is_expired(self, now_mono: float) -> bool:
        return now_mono >= self.expires_at_mono
```

> 期限判定に `time.monotonic()` を使うのは、システム時計のずれ/NTP 補正で TTL が伸縮しないようにするため。`created_at` は監査ログ表示専用。

### 4.2 API モデル `app/models/api.py`

```python
from pydantic import BaseModel, Field

class CredentialRequest(BaseModel):
    credential_id: str = Field(min_length=1, max_length=64)  # 未知IDは config lookup で 404

class CredentialResponse(BaseModel):
    handle: str
    expires_in: int

class ExecuteRequest(BaseModel):
    credential_handle: str = Field(min_length=8, max_length=64, pattern=r"^cred_[A-Za-z0-9_-]+$")
    action: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    parameters: dict = Field(default_factory=dict)

class ExecuteResponse(BaseModel):
    status: str            # "success"
    data: dict | list

class RevokeRequest(BaseModel):
    credential_handle: str = Field(pattern=r"^cred_[A-Za-z0-9_-]+$")

class RevokeResponse(BaseModel):
    status: str            # "revoked"

class CapabilityItem(BaseModel):
    credential_id: str
    description: str
    allowed_actions: list[str]

class CapabilitiesResponse(BaseModel):
    credentials: list[CapabilityItem]

class ErrorResponse(BaseModel):
    error: str
```

- `action` は pattern（`^[a-z0-9_]+$`）で **path traversal 文字（`/ . \`）を弾く**。`credential_id` は pattern を持たず長さ制限のみで、config の完全一致 lookup に外れたものはすべて「存在しない credential_id」になる（実装 `app/models/api.py`）。`../../.env` や `secret/data/root` は 422 ではなく「存在しない credential_id」として扱いたいので、**pattern バリデーションで落ちたら 404 `UNKNOWN_CREDENTIAL` に正規化する**（§8 のハンドラで変換。TEST-005/006 対応）。

### 4.3 設定モデル `app/models/config.py`

```python
class CredentialConfig(BaseModel):
    provider: str                       # "dotenv" (v0.1 は dotenv のみ許可)
    secret_name: str                    # ".env のキー名"。サーバ側固定。AI へは出さない
    connector: str                      # "github"
    description: str                    # /capabilities で AI に見せる説明
    ttl: int = 300
    allowed_actions: list[str]

class RateLimitConfig(BaseModel):
    request_per_min: int = 20
    execute_per_min: int = 60

class BrokerConfig(BaseModel):
    default_ttl: int = 300
    max_ttl: int = 900
    cleanup_interval_sec: int = 10
    max_response_bytes: int = 1_048_576     # 1 MiB
    max_response_items: int = 200
    rate_limit: RateLimitConfig = RateLimitConfig()
    credentials: dict[str, CredentialConfig]
```

ロード時バリデーション（`config_loader.py`）:
- `credentials` のキー（= credential_id）が `^[a-z0-9_]+$` に一致すること。
- `provider` が既知（v0.1 は `{"dotenv"}`）。
- `connector` が `actions/registry.py` に登録済みであること。
- `allowed_actions` の各要素が connector の既知アクション集合の部分集合であること（未知なら起動失敗）。
- `ttl <= max_ttl` であること。
- 違反はすべて**起動時例外**（fail-closed、稼働後に不整合が出ない）。

---

## 5. `config/credentials.yaml`（確定・v0.1 実値）

```yaml
default_ttl: 300
max_ttl: 900
cleanup_interval_sec: 10
max_response_bytes: 1048576
max_response_items: 200

rate_limit:
  request_per_min: 20
  execute_per_min: 60

credentials:
  github_reader:
    provider: dotenv
    secret_name: GITHUB_TOKEN        # .env のキー。AI には絶対に見せない
    connector: github
    description: "Read-only access to GitHub repositories and issues"
    ttl: 300
    allowed_actions:
      - list_repositories
      - get_repository
      - list_issues
      - get_issue
```

- この YAML は **サーバ側固定**。API 経由で変更する経路は作らない（SR-005）。
- `.env.example`:
  ```
  # 実値は起動時に secret store から生成（deploy/fetch-secrets.sh）
  GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
  ```

---

## 6. GitHub Action 定義（確定）

`app/actions/github.py` に以下 4 つを `ActionSpec` として定義。共通:

- base URL: `https://api.github.com`（**固定・パラメータで変更不可 = SSRF 防止**）
- 共通ヘッダ:
  - `Authorization: Bearer <secret>`（実行直前に組み立て）
  - `Accept: application/vnd.github+json`
  - `X-GitHub-Api-Version: 2022-11-28`
  - `User-Agent: credential-broker/0.1`
- timeout: connect 5s / read 15s（`httpx.Timeout`）
- リダイレクト追従: **無効**（`follow_redirects=False`）
- レスポンスは必ず sanitizer を通す（§7）。生 JSON をそのまま返さない。

### 6.1 `list_repositories`

| 項目 | 値 |
|------|-----|
| method / path | `GET /user/repos` |
| query params（すべて任意） | `visibility` ∈ {all, public, private}（既定 all） / `affiliation`（既定 `owner`）/ `sort` ∈ {created, updated, pushed, full_name} / `per_page` ∈ 1..100（既定 30）/ `page` ≥ 1（既定 1） |
| パラメータモデル | `ListRepositoriesParams`（pydantic、上記 enum/range で検証。未知キーは `model_config = ConfigDict(extra="forbid")` で 422→INVALID_PARAMETER） |
| sanitize allowlist（配列各要素） | `id, name, full_name, private, html_url, description, fork, default_branch, language, updated_at, pushed_at, archived, visibility` |

### 6.2 `get_repository`

| 項目 | 値 |
|------|-----|
| method / path | `GET /repos/{owner}/{repo}` |
| path params | `owner` `^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$` / `repo` `^[A-Za-z0-9._-]{1,100}$` |
| query params | なし |
| sanitize allowlist | `id, name, full_name, private, html_url, description, default_branch, language, topics, license.spdx_id, stargazers_count, forks_count, open_issues_count, created_at, updated_at, pushed_at, archived, visibility` |

### 6.3 `list_issues`

| 項目 | 値 |
|------|-----|
| method / path | `GET /repos/{owner}/{repo}/issues` |
| path params | `owner` / `repo`（6.2 と同じ regex） |
| query params | `state` ∈ {open, closed, all}（既定 open）/ `labels`（`^[A-Za-z0-9 ,_\-]{0,200}$`）/ `sort` ∈ {created, updated, comments} / `direction` ∈ {asc, desc} / `per_page` 1..100 / `page` ≥ 1 |
| sanitize allowlist（各要素） | `number, title, state, html_url, user.login, labels[].name, comments, created_at, updated_at, closed_at, draft, pull_request(bool: 存在有無のみ→`is_pull_request`)` |

> `body`（Issue 本文）は **v0.1 では返さない**（本文にトークン等が貼られている事故があるため。返すなら sanitizer のパターンマスクを通す。§7.2）。

### 6.4 `get_issue`

| 項目 | 値 |
|------|-----|
| method / path | `GET /repos/{owner}/{repo}/issues/{number}` |
| path params | `owner` / `repo` / `number` int ≥ 1 |
| sanitize allowlist | 6.3 と同じ + `body_preview`（body 先頭 2,000 文字を §7.2 のパターンマスク適用後に格納） |

### 6.5 `ActionSpec` 形（`app/actions/base.py`）

```python
@dataclass(frozen=True)
class ActionSpec:
    name: str
    method: str                       # "GET"
    path_template: str                # "/repos/{owner}/{repo}/issues/{number}"
    param_model: type[BaseModel]      # path+query をまとめて検証
    query_fields: frozenset[str]      # param_model のうち query に載せるフィールド
    path_fields: frozenset[str]       # path_template に埋めるフィールド
    sanitize: Callable[[Any], Any]    # allowlist 抽出関数
```

---

## 7. Sanitizer / Validation

### 7.1 `security/validation.py`

- action ごとの `param_model` に `parameters` dict を流し込む。
- `extra="forbid"` で未知キーは弾く → `INVALID_PARAMETER`。
- 型/enum/range 違反 → `INVALID_PARAMETER`。
- path フィールドは追加で「URL エンコード後に `/` `..` を含まない」ことを assert（regex で担保済みだが二重防御）。

### 7.2 `security/sanitizer.py`

2 段階:

1. **allowlist 抽出**: GitHub レスポンス JSON から §6 で定義したフィールドのみを再構築（ネストは dotted path で指定）。それ以外は捨てる。
2. **パターンマスク**（テキストフィールドに対して）:
   - `ghp_[A-Za-z0-9]{36}` / `github_pat_[A-Za-z0-9_]{22,}` / `gho_` `ghu_` `ghs_` `ghr_` 系
   - `xox[baprs]-[A-Za-z0-9-]+`（Slack）
   - `AKIA[0-9A-Z]{16}`（AWS）
   - `-----BEGIN [A-Z ]*PRIVATE KEY-----`
   - `Bearer\s+[A-Za-z0-9._\-]+`
   - `sk-[A-Za-z0-9]{20,}`
   - マッチは `***REDACTED***` に置換。
3. **サイズ / 件数上限**: `max_response_bytes` 超なら `PROVIDER_ERROR`（内部詳細は返さない）。配列は `max_response_items` で truncate し `"truncated": true` を添える。

### 7.3 レスポンスヘッダ

- GitHub レスポンスの**ヘッダは一切転送しない**（`Authorization` エコー・`Set-Cookie`・`X-*` 全部落とす）。
- Broker が返すのは sanitize 済み JSON ボディのみ。

---

## 8. HTTP API（FastAPI・確定）

全エンドポイント: `Depends(require_broker_token)` を付与。`Content-Type: application/json`。

### 8.1 `POST /credentials/request`

```
Req:  { "credential_id": "github_reader" }
Res 200: { "handle": "cred_xxx", "expires_in": 300 }
```

処理（`broker.issue()`）:
1. レート制限チェック（`request_per_min`）。超過 429 `RATE_LIMITED`。**存在確認より先に行う**（未知IDの大量送信で制限をすり抜けたり、監査ログ・異常検知を溢れさせたりできないように）。
2. `credential_id` を config から引く。無ければ **404 `{"error":"UNKNOWN_CREDENTIAL"}`**。
3. `provider = providers[cfg.provider]`; `secret = provider.get_secret(cfg.secret_name)`。
   - Provider 失敗 → 502 `{"error":"CREDENTIAL_PROVIDER_ERROR"}`（内部詳細ログのみ、レスポンスに出さない）。
4. `handle = "cred_" + secrets.token_urlsafe(24)`。
5. `ttl = min(cfg.ttl, max_ttl)`。
6. `TemporaryCredential` を作り `store.put(handle, cred)`。SecretRegistry に secret 登録（ログ redaction 用）。
7. audit: `credential_issued`（handle は sha256、secret は出さない）。
8. `CredentialResponse(handle=handle, expires_in=ttl)`。

### 8.2 `POST /execute`

```
Req:  { "credential_handle": "cred_xxx", "action": "list_repositories", "parameters": {} }
Res 200: { "status": "success", "data": {...} | [...] }
```

処理（`broker.execute()`）:
1. レート制限（`execute_per_min`）。
2. `cred = store.get(handle)`。無ければ **410 `{"error":"EXPIRED_HANDLE"}`**（存在しない・失効済みを区別しない ＝ handle 探索を助けない）。
3. `if cred.is_expired(now_mono): store.pop(handle); return 410 EXPIRED_HANDLE`。
4. `PolicyEngine.check(cred, action, parameters)`:
   - `action not in cred.allowed_actions` → **403 `{"error":"ACTION_NOT_ALLOWED"}`**。
   - connector の `ActionSpec` を取得。無ければ 403 `ACTION_NOT_ALLOWED`（存在しない action も同一扱い）。
   - `param_model` で `parameters` 検証 → 失敗 **422 `{"error":"INVALID_PARAMETER"}`**。
5. `executor = registry.get(cred.connector)`。
6. `result = await executor.run(spec, validated_params, secret=cred.secret)`。
   - httpx 呼び出し。GitHub が 4xx/5xx → ステータス別マッピング（§8.4）。
   - 例外は握って `PROVIDER_ERROR`（スタック・URL・secret を含めない）。
7. `data = spec.sanitize(result.body)`; サイズ/件数チェック。
8. audit: `action_executed`（action, result, duration_ms, upstream_status）。
9. `ExecuteResponse(status="success", data=data)`。

> handle は §8.2-3 の判定後も executor の `await` 中に revoke されうるが、v0.1 では**実行中リクエストは完走**させる（secret はステップ 6 開始前に取得済み）。この挙動は README に明記。

### 8.3 `POST /credentials/revoke`

```
Req:  { "credential_handle": "cred_xxx" }
Res 200: { "status": "revoked" }
```

- `store.pop(handle)`（存在しなくても 200 `revoked` を返す ＝ 冪等・存在漏洩なし）。
- SecretRegistry からも該当 secret を deregister（他 handle が同 secret を参照していなければ）。
- audit: `credential_revoked`。

### 8.4 `GET /capabilities`

```
Res 200: { "credentials": [ { "credential_id": "...", "description": "...", "allowed_actions": [...] } ] }
```

- config の `credentials` から `credential_id` / `description` / `allowed_actions` **のみ**を返す。
- `provider` / `secret_name` / `connector` / `ttl` は**返さない**（SR-004, §21）。

### 8.5 エラー ↔ HTTP ステータス対応表

| error コード | HTTP | 発生条件 |
|--------------|------|----------|
| `UNAUTHORIZED` | 401 | Broker トークン不正/欠如 |
| `RATE_LIMITED` | 429 | ウィンドウ超過 |
| `UNKNOWN_CREDENTIAL` | 404 | credential_id が config に無い / pattern 違反（正規化） |
| `EXPIRED_HANDLE` | 410 | handle 不明 or TTL 満了 or revoke 済み |
| `ACTION_NOT_ALLOWED` | 403 | allowed_actions 外 / 未知 action |
| `INVALID_PARAMETER` | 422 | パラメータ検証失敗 |
| `CREDENTIAL_PROVIDER_ERROR` | 502 | Secret 取得失敗 |
| `PROVIDER_ERROR` | 502 | 外部 API 実行失敗 / レスポンス過大 |

- **全エラーレスポンスは `{"error": "<CODE>"}` の 1 キーのみ**。message / detail / stack は付けない（SR-003）。
- FastAPI の `RequestValidationError`（pydantic）も上表へ正規化するカスタム exception handler を入れる（既定の 422 詳細ボディを漏らさない）。

---

## 9. セキュリティ要件 実装対応表（SR-001〜010）

| SR | 実装 |
|----|------|
| SR-001 Secret を API レスポンスに含めない | `/credentials/request` は handle のみ。`/execute` は sanitize 済み。sanitizer にパターンマスク。テスト `test_broker.py::test_request_returns_handle_only` / `test_injection.py::test_execute_response_has_no_secret` |
| SR-002 Secret をログに書かない | `redaction.py` の logging.Filter を root logger に装着 + AuditLogger は構造化フィールドのみ受け付け（自由文字列を取らない）。テスト `test_logging.py` |
| SR-003 例外に Secret を含めない | `BrokerError` は `error_code` のみ保持。executor は upstream 例外を捕捉し `PROVIDER_ERROR` に潰す。httpx の `request`/`response` オブジェクトを例外メッセージに含めない |
| SR-004 AI が任意 Secret 名を指定不可 | API 入力は `credential_id`（`^[a-z0-9_]+$`）のみ。`secret_name` は config 内部。`get_secret` を叩く公開エンドポイント無し。テスト `test_injection.py::test_no_raw_secret_endpoint` |
| SR-005 Mapping はサーバ側固定 | `credentials.yaml` はロード専用。更新 API 無し。ファイルは `chmod 640` |
| SR-006 Allowlist 方式 | `PolicyEngine` が `cred.allowed_actions` と `ActionSpec` 登録の二重 allowlist。デフォルト拒否 |
| SR-007 Handle エントロピー | `secrets.token_urlsafe(24)` = 192bit |
| SR-008 Handle に推測可能情報を含めない | prefix `cred_` + ランダムのみ。credential_id / timestamp を埋め込まない |
| SR-009 期限切れ Handle 再利用不可 | `store.get` が期限チェック + `pop`。CleanupWorker が定期削除。同じ handle 文字列は再生成されない（ランダム） |
| SR-010 Secret をディスクに書かない | Store は dict のみ。ログ redaction。tmpfs `.env` は Provider の read 対象（Broker が書くのではなく systemd が用意） |

---

## 10. ロギング設計

### 10.1 `security/redaction.py`

```python
class SecretRegistry:
    """現在有効な Secret 値の集合。ログ redaction とテスト検証に使う。"""
    _values: set[str]
    def register(self, secret: str) -> None: ...
    def deregister(self, secret: str) -> None: ...   # 参照カウントで管理
    def snapshot(self) -> frozenset[str]: ...

class RedactionFilter(logging.Filter):
    """レコードの msg / args を走査し、登録 Secret とパターンを *** に置換。"""
    def filter(self, record: logging.LogRecord) -> bool:
        # 1) record.getMessage() を組み立て
        # 2) SecretRegistry.snapshot() の各値を "***" に replace
        # 3) §7.2 のパターンを replace
        # 4) record.msg を書き換え、record.args = ()
        return True
```

- root logger と uvicorn logger の両方に装着（`logging.getLogger().addFilter(...)` + `dictConfig`）。
- **多層防御**であって主防御ではない。第一に「Secret をロガーに渡さない」。

### 10.2 `security/audit.py` — AuditLogger

構造化 JSON を 1 行 1 イベントで出力（stdout / ファイル）。**受け取れるのは決められたフィールドだけ**（自由文字列引数を取らない API にする）。

記録するフィールド（仕様 §18 準拠）:

```json
{
  "ts": "2026-09-09T12:30:00+09:00",
  "event": "action_executed",
  "credential_id": "github_reader",
  "handle_sha256": "9f2c...",          // handle の sha256 hex（先頭 16 文字）
  "action": "list_repositories",
  "result": "success",
  "upstream_status": 200,
  "duration_ms": 143,
  "client_id": "agent",
  "expires_at": "2026-09-09T12:35:00+09:00"
}
```

イベント種別: `credential_issued` / `action_executed` / `credential_revoked` / `credential_expired` / `policy_denied` / `provider_error` / `rate_limited` / `auth_failed`。

**禁止フィールド**（型レベルで渡せないようにする）: API key / token / Authorization / Vault token / secret_name / .env パス / secret_name。`secret_name` すら監査に出さない（§21）。

---

## 11. 並行性・ライフサイクル

- FastAPI `lifespan`:
  - 起動: config ロード → バリデーション → providers 初期化 → `httpx.AsyncClient` 生成（コネクションプール共有）→ `CleanupWorker` を `asyncio.create_task` で起動。
  - 終了: CleanupWorker キャンセル → 全 TemporaryCredential を `store.clear()`（secret 参照破棄）→ `httpx.AsyncClient.aclose()`。
- `CredentialStore` は単一イベントループ前提。`get`→`pop` の間に `await` を挟まないので **ロック不要**。ただし将来のマルチワーカー化に備え `asyncio.Lock` を持たせておく（no-op 同然のコスト）。
- **uvicorn は `--workers 1` 固定**（メモリ Store をプロセス間共有できないため。マルチワーカーは v0.2 で Redis Store 化とセット）。
- 時計: 期限は `time.monotonic()`。テスト用に `CredentialStore(clock=time.monotonic)` を DI 可能にする。

### 11.1 `CleanupWorker`（`app/cleanup.py`）

```python
async def run(store: CredentialStore, interval: int, audit: AuditLogger, registry: SecretRegistry):
    while True:
        await asyncio.sleep(interval)
        now = time.monotonic()
        for handle in store.expired_handles(now):
            cred = store.pop(handle)
            registry.deregister(cred.secret)
            audit.emit("credential_expired", credential_id=cred.credential_id,
                       handle_sha256=sha16(handle))
```

---

## 12. テスト設計（pytest・受け入れテスト対応）

### 12.1 `conftest.py` の要点

```python
@pytest.fixture
def fake_clock():
    class Clock:
        t = 1000.0
        def __call__(self): return self.t
        def advance(self, s): self.t += s
    return Clock()

@pytest.fixture
def broker_env(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("GITHUB_TOKEN=ghp_TESTTOKEN000000000000000000000000000000\n")
    monkeypatch.setenv("BROKER_API_TOKEN", "test-broker-token")
    monkeypatch.setenv("DOTENV_PATH", str(env))
    monkeypatch.setenv("CONFIG_PATH", "config/credentials.yaml")
    ...

@pytest.fixture
async def client(broker_env, fake_clock):
    app = create_app(clock=fake_clock)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        c.headers["Authorization"] = "Bearer test-broker-token"
        yield c

@pytest.fixture
def gh_mock(respx_mock):
    respx_mock.get("https://api.github.com/user/repos").respond(json=[{...full payload with secrets...}])
    ...
```

GitHub モックのペイロードには**わざと `body` に `ghp_REALLOOKINGTOKEN...` を仕込む**（sanitizer / redaction の検証用）。

### 12.2 受け入れテスト対応表

| 仕様テスト | pytest | 検証内容 |
|-----------|--------|---------|
| TEST-001 Secret 非開示 | `test_broker.py::test_request_returns_handle_only` | `/credentials/request` レスポンス全文に `GITHUB_TOKEN` の値・`ghp_` が現れない。キーは `handle`, `expires_in` のみ |
| TEST-002 TTL | `test_ttl.py::test_expired_after_ttl` | request → `fake_clock.advance(301)` → execute → 410 `EXPIRED_HANDLE` |
| TEST-003 Revoke | `test_broker.py::test_revoke_then_execute_fails` | request → revoke(200) → execute → 410 |
| TEST-004 未認可 Action | `test_policy.py::test_delete_repository_denied` | `action="delete_repository"` → 403 `ACTION_NOT_ALLOWED` |
| TEST-005 Secret 列挙 | `test_injection.py::test_physical_secret_name_rejected` | `credential_id="OPENAI_API_KEY"` → 404 `UNKNOWN_CREDENTIAL`（pattern 違反も同じ結果） |
| TEST-006 Path Traversal | `test_injection.py::test_path_traversal_rejected` | `credential_id="../../.env"` → 404 `UNKNOWN_CREDENTIAL` |
| TEST-007 Prompt Injection | `test_injection.py::test_no_secret_endpoint` | ルート一覧に Secret 取得系が無い（`{r.path for r in app.routes}` を assert）。`/execute` の action に自然文を渡しても 403 |
| TEST-008 ログ漏洩 | `test_logging.py::test_no_secret_in_captured_logs` | 全フロー（request→execute→revoke）を回し `caplog.text` + AuditLogger 出力に実トークン・`Bearer ghp_`・`body` 内の埋め込みトークンが出ない |

追加テスト:
- `test_provider.py::test_dotenv_unknown_key_raises` / `::test_dotenv_never_logs_value`
- `test_actions_github.py::test_sanitize_strips_unlisted_fields` / `::test_response_size_cap` / `::test_upstream_404_maps_to_provider_error`
- `test_capabilities.py::test_capabilities_hides_secret_name`
- `test_broker.py::test_missing_broker_token_401`
- `test_ttl.py::test_cleanup_worker_removes_expired`（worker を直接 await）

カバレッジ目標: `broker.py` / `policy.py` / `sanitizer.py` / `store.py` は 90%+。

---

## 13. デプロイ

### 13.1 配置

```
/opt/credential-broker                           # コード（git、.venv）※配置先は環境依存・公開物にはベタ書きしない
/run/credential-broker/                          # tmpfs（systemd RuntimeDirectory）
  └── .env                                       # Vault 由来・chmod 600・stop で消える
```

### 13.2 Secret store の準備（要作成）

任意の secret store（HashiCorp Vault 等）に、この Broker 用の secret を1つ作り、2フィールド入れる:

| フィールド | 用途 |
|-----------|------|
| `github_token` | GitHub fine-grained PAT（read-only: Contents=Read, Metadata=Read, Issues=Read） |
| `broker_api_token` | `openssl rand -hex 32` で生成。エージェント ⇔ Broker |

> 既存の GitHub トークンを流用するより、**read-only 専用の fine-grained PAT を新規発行**するのを推奨（スコープを最小化できる）。

### 13.3 `deploy/fetch-secrets.sh`（ExecStartPre）

secret store から `/run/credential-broker/{.env,broker.env}`（tmpfs、chmod 600）へ materialise する。
接続先（`VAULT_ADDR` / `VAULT_CACERT` / secret path）は環境変数で渡す。実装は `deploy/fetch-secrets.sh` を参照。

- **1フィールドずつ取得**（secret 全体をダンプしない）。出力を echo/grep で確認しない。

### 13.4 `deploy/credential-broker.service`

```ini
[Unit]
Description=AI Credential Broker (v0.1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cbroker
WorkingDirectory=/opt/credential-broker
RuntimeDirectory=credential-broker
RuntimeDirectoryMode=0700
ExecStartPre=/opt/credential-broker/deploy/fetch-secrets.sh
EnvironmentFile=/run/credential-broker/broker.env
Environment=DOTENV_PATH=/run/credential-broker/.env
Environment=CONFIG_PATH=/opt/credential-broker/config/credentials.yaml
ExecStart=/opt/credential-broker/.venv/bin/uvicorn --factory app.main:create_app --host 127.0.0.1 --port 8787 --workers 1
ExecStopPost=/bin/rm -f /run/credential-broker/.env /run/credential-broker/broker.env
Restart=on-failure
RestartSec=3
# ハードニング
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/credential-broker
ProtectKernelTunables=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

> systemd 登録は本書では unit ファイルを用意するのみ。実際の導入は運用者判断で。

### 13.5 エージェント側の使い方（v0.1）

- Claude Code / Codex からは素の HTTP（httpx / curl）で `http://127.0.0.1:8787` を叩く。
- `Authorization: Bearer <BROKER_API_TOKEN>`（secret store から取得した値）。
- **v0.1.5 の推奨**: 薄い MCP サーバ（tools: `list_capabilities`, `request_credential`, `execute`, `revoke`）でラップすると、ツールコール引数が構造的に `credential_id` / `action` / `parameters` に固定され仕様 §20 と完全に整合。MCP スキルの雛形あり（`mcp-server-builder`）。

---

## 14. 実装順序（PR 分割・Codex/Claude へ渡す単位）

| PR | 内容 | 完了条件 |
|----|------|---------|
| PR1 | skeleton: `main.py` / `settings.py` / `config_loader.py` / models / `deps.require_broker_token` / `GET /capabilities` / errors handler | `test_capabilities.py` / `test_broker.py::test_missing_broker_token_401` green。Secret には一切触れない |
| PR2 | `providers/base.py` + `dotenv.py` / `CredentialStore`（clock DI）/ `CleanupWorker` / `POST /credentials/request` / `POST /credentials/revoke` | `test_provider.py` / `test_ttl.py` / `test_broker.py::test_request_returns_handle_only` / `::test_revoke_*` green |
| PR3 | `actions/base.py` + `github.py`（4 アクション）/ `registry.py` / `PolicyEngine` / `validation.py` / `sanitizer.py` / `POST /execute` | `test_policy.py` / `test_actions_github.py` / `test_injection.py` green（respx モック） |
| PR4 | `redaction.py`（Filter + SecretRegistry）/ `audit.py` / `ratelimit.py` / README / `.env.example` / deploy 一式 | `test_logging.py` green、`ruff` clean、全テスト green、カバレッジ確認 |
| — | **公開前レビュー**: push 前にセキュリティ&品質レビュー → PASS を記録 | レビュー PASS 記録あり |

各 PR は「テスト先行（該当受け入れテストを先に書く）」で進める（`tdd-workflow` スキル準拠）。

---

## 15. v0.2 以降への拡張ポイント（設計を壊さない差し込み位置）

| 追加要素 | 差し込み位置 | 既存への影響 |
|----------|-------------|-------------|
| Vault Provider | `providers/vault.py` を `SecretProvider` 実装、`config_loader` の許可 provider に追加、YAML の `provider: vault` / `secret_name: <KV パス>` | なし（`get_secret` 契約のみ） |
| Environment Provider | 同上 `providers/environment.py` | なし |
| 複数 credential（openai_generation 等） | `credentials.yaml` に追記 + `actions/openai.py` を registry 登録 | なし |
| Audit DB | `AuditLogger` に sink を追加（現状 stdout → +SQLite/Postgres） | なし（emit API 不変） |
| NekoGuard 連携 | `AuditLogger` sink に HTTP push を追加。イベント形状は §10.2 で確定済み | なし |
| Rate limit 強化 / per-agent | `ratelimit.py` を Redis バックエンドに、`client_id` を Broker トークン → agent マップから解決 | `client_id` は既にモデルにある |
| マルチワーカー | `CredentialStore` を Redis 実装に差し替え（`get`/`put`/`pop`/`expired_handles` 契約維持）、`--workers N` | Store インターフェースのみ |
| Secret 物理ゼロ化 | `SecretBox(bytearray)` を導入し `TemporaryCredential.secret` の型を変更、executor のヘッダ組み立てを `bytes` 経由に | executor / store の内部のみ |
| Write Action + Human Approval | `PolicyEngine` に `risk` 判定（read=auto / write=policy / delete=approval）、`actions/*.py` に write spec | `PolicyEngine.check` の戻り値を `Decision`（allow/deny/needs_approval）に拡張 |
| Dynamic Credentials（短命トークン） | `SecretProvider` に `supports_lease` を足し、`get_secret` を `acquire_lease() -> Lease(secret, ttl)` に拡張。Broker の TTL を lease TTL に同期 | Provider 契約の拡張（後方互換ラッパ可） |

---

## 16. 最小完成条件チェックリスト（仕様 §30 対応）

- [ ] `.env`（tmpfs / Vault 由来）から `github_reader` の Secret を取得できる
- [ ] AI から `.env` を直接読む経路が存在しない（ルート一覧テスト）
- [ ] `/credentials/request` / `/execute` のどのレスポンスにも Secret 値が出ない
- [ ] `handle` = `cred_` + 192bit random を発行
- [ ] TTL 300s、301s 後は `EXPIRED_HANDLE`
- [ ] `CleanupWorker` が期限切れを定期削除
- [ ] `/credentials/revoke` で即時無効化（冪等）
- [ ] GitHub read 4 アクションを代理実行できる（respx で検証、実 API で 1 回スモーク）
- [ ] allowlist 外 action → `ACTION_NOT_ALLOWED`
- [ ] `credential_id` に物理 Secret 名 / path traversal → `UNKNOWN_CREDENTIAL`
- [ ] 全ログ・監査に実 Secret / `Bearer` トークンが出ない（grep テスト）
- [ ] Broker トークン無し → 401
- [ ] `ruff` clean / 全テスト green / 対象モジュール カバレッジ 90%+
- [ ] 公開前レビュー PASS を記録（push はその後）

---

## 付録 A. 主要クラスのシグネチャ（実装の型合わせ用）

```python
# providers/base.py
class SecretProvider(ABC):
    @abstractmethod
    def get_secret(self, secret_name: str) -> str: ...

# providers/dotenv.py
class DotEnvProvider(SecretProvider):
    def __init__(self, dotenv_path: str) -> None: ...   # 起動時に 1 回 parse、dict 保持
    def get_secret(self, secret_name: str) -> str: ...  # 未知キー → ProviderError

# store.py
class CredentialStore:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None: ...
    def put(self, cred: TemporaryCredential) -> None: ...
    def get(self, handle: str) -> TemporaryCredential | None: ...   # 期限切れなら pop して None
    def pop(self, handle: str) -> TemporaryCredential | None: ...
    def expired_handles(self, now_mono: float) -> list[str]: ...
    def clear(self) -> None: ...

# policy.py
@dataclass
class PolicyDecision:
    allowed: bool
    error_code: str | None
    spec: ActionSpec | None
    validated_params: BaseModel | None

class PolicyEngine:
    def __init__(self, registry: ActionRegistry) -> None: ...
    def check(self, cred: TemporaryCredential, action: str, parameters: dict) -> PolicyDecision: ...

# actions/base.py
@dataclass
class ActionResult:
    upstream_status: int
    body: Any
    duration_ms: int

class ActionExecutor(ABC):
    @abstractmethod
    async def run(self, spec: ActionSpec, params: BaseModel, *, secret: str) -> ActionResult: ...

# actions/github.py
class GitHubReadExecutor(ActionExecutor):
    def __init__(self, http: httpx.AsyncClient, base_url: str = "https://api.github.com") -> None: ...
    async def run(self, spec, params, *, secret) -> ActionResult: ...

# broker.py
class CredentialBroker:
    def __init__(self, config: BrokerConfig, providers: dict[str, SecretProvider],
                 store: CredentialStore, policy: PolicyEngine, registry: ActionRegistry,
                 audit: AuditLogger, secret_registry: SecretRegistry,
                 limiter: SlidingWindowLimiter) -> None: ...
    def issue(self, credential_id: str, client_id: str) -> CredentialResponse: ...       # raises BrokerError
    async def execute(self, handle: str, action: str, parameters: dict,
                      client_id: str) -> ExecuteResponse: ...
    def revoke(self, handle: str) -> RevokeResponse: ...
    def capabilities(self) -> CapabilitiesResponse: ...

# errors.py
class BrokerError(Exception):
    def __init__(self, error_code: str, http_status: int) -> None: ...
# UnknownCredential(404) / ExpiredHandle(410) / ActionNotAllowed(403) /
# InvalidParameter(422) / CredentialProviderError(502) / ProviderError(502) / RateLimited(429)
```

## 付録 B. リポジトリ初期化時の注意（セキュリティ hook）

- `git init` 直後、最初のコミット前に `.gitignore` を作成（`.env`, `.env.*`, `.venv/`, `__pycache__/`, `*.log`, `.claude/`, `config/*.local.yaml`）。
- セキュリティ precheck hook は Claude の cwd の `.gitignore` を見る。`credential-broker/` で作業するなら同ディレクトリに `.gitignore` を置く。
- GitHub push は **Codex 相互レビュー PASS 後**。push 前に `git log -p` で Secret 混入がないか確認。
