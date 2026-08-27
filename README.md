# s12ryt-ssh Authentication Server

此目錄提供 Node.js 22 身分驗證與代理服務。最高管理員透過 Telegram Bot 管理子帳號、S3/MySQL/PostgreSQL connection、operation grants、裝置 session 與稽核；Windows GUI 的「登入校驗」模式只取得短期 session，所有 S3/SQL 操作都由服務端代理。

## 安全邊界

- S3 access key、secret key、SQL user 與 password 只保存在服務端 SQLite 的 AES-256-GCM 密文中。
- 子帳號密碼以 `scrypt` 與隨機 salt 保存，Bot 產生的密碼只顯示一次。
- access token 是約 15 分鐘的 opaque token，只存在桌面客戶端記憶體。
- refresh token 預設有效 30 天，每次使用即輪換；SQLite 只保存 SHA-256 hash，重用舊 token 會撤銷該 token family。
- Windows GUI 使用 DPAPI 保存 refresh token；URL、帳號與 device ID 另存於非敏感偏好檔，密碼不落盤。
- 稽核只保存安全 metadata。SQL 只記錄 statement hash/type，不保存完整 statement；S3 不保存 object body。

Telegram 的私聊訊息仍會先經過 Telegram 平台。Bot 會盡力刪除 connection wizard 中的 access key、secret key 與資料庫密碼訊息，但不能宣稱 Telegram 從未接收或保存該訊息。正式環境應使用專用、可輪換且具最小權限的 credentials。

## 環境需求

- Node.js `22.13.0` 或更新版本。
- npm。
- Telegram Bot token，以及一個或多個最高管理員 numeric user ID。
- 一個隨機 32-byte Base64 主金鑰。
- 可由服務端連線的 S3 相容 endpoint、MySQL/MariaDB 或 PostgreSQL。

## 安裝與啟動

```powershell
Set-Location server
npm ci
Copy-Item .env.example .env
```

產生主金鑰：

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

完成 `.env` 後執行：

```powershell
npm run build
npm start
```

開發模式：

```powershell
npm run dev
```

啟動時會在 transaction 中自動套用版本化 SQLite migration。migration 失敗會使服務停止，不會帶著半完成 schema 繼續接受請求。

## 環境變數

| 變數                        | 必填 | 預設             | 說明                                                               |
| --------------------------- | ---- | ---------------- | ------------------------------------------------------------------ |
| `BOT_TOKEN`                 | 是   | 無               | Telegram BotFather 提供的 Bot token。                              |
| `TELEGRAM_ADMIN_IDS`        | 是   | 無               | 逗號分隔的正整數 Telegram user ID；只有這些帳號可使用管理功能。    |
| `MASTER_KEY_BASE64`         | 是   | 無               | 解碼後必須正好 32 bytes，用於 AES-256-GCM connection secret 加密。 |
| `SQLITE_PATH`               | 否   | `./data/auth.db` | 服務自身 SQLite 路徑。                                             |
| `HOST`                      | 否   | `127.0.0.1`      | Fastify listen host。                                              |
| `PORT`                      | 否   | `8787`           | Fastify listen port。                                              |
| `TRUSTED_PROXIES`           | 否   | 空               | 逗號分隔的可信 IP/CIDR；只有明確填入時才信任 forwarded headers。   |
| `ALLOW_INSECURE_HTTP`       | 否   | `false`          | 允許非 loopback HTTP 登入。正式環境不應開啟。                      |
| `ACCESS_TOKEN_TTL_SECONDS`  | 否   | `900`            | access token TTL。                                                 |
| `REFRESH_TOKEN_TTL_SECONDS` | 否   | `2592000`        | rotation refresh token TTL。                                       |
| `DEFAULT_DEVICE_LIMIT`      | 否   | `3`              | 新子帳號預設同時登入裝置上限。                                     |
| `SQL_TIMEOUT_MS`            | 否   | `30000`          | SQL query/exec timeout。                                           |
| `SQL_ROW_LIMIT`             | 否   | `1000`           | SQL query 最大回傳列數。                                           |
| `S3_MAX_BYTES`              | 否   | `104857600`      | 單次 S3 upload/download byte 上限。                                |
| `AUDIT_RETENTION_DAYS`      | 否   | `90`             | 稽核保存天數；runtime 每日清理一次。                               |
| `LOGIN_RATE_LIMIT`          | 否   | `10`             | 每分鐘 login/refresh request 上限。                                |
| `API_RATE_LIMIT`            | 否   | `120`            | 每分鐘全域 API request 上限。                                      |

`.env`、`data/`、SQLite、`node_modules/` 與 `dist/` 已由 repository `.gitignore` 排除。不要把真實 token、主金鑰或 connection secret 提交到 Git。

## HTTPS 與反向代理

服務允許 loopback HTTP，方便同機開發。非 loopback request 若不是 HTTPS，且 `ALLOW_INSECURE_HTTP=false`，login/refresh 會回 `https_required`。

正式部署建議：

1. Fastify 只監聽 `127.0.0.1:8787` 或私有網路介面。
2. 由 Caddy、Nginx 或 Cloudflare Tunnel 終止 TLS。
3. `TRUSTED_PROXIES` 只填實際反向代理 IP/CIDR，不要無條件信任所有來源。
4. GUI 填入完整 HTTPS base URL，例如 `https://auth.example.com`；若 API 掛在子路徑，亦可使用 `https://example.com/s12ryt`。

直接將 Fastify 暴露到公開網路時，必須自行配置可靠的 TLS 終止、來源限制、更新策略與監控。

## Telegram Bot 管理

Bot 只處理私聊。群組訊息會被忽略；不在 `TELEGRAM_ADMIN_IDS` 的使用者會收到未授權訊息。首次語言依 Telegram `language_code` 判斷，`zh*` 使用繁體中文，其餘使用英文；管理員偏好保存在 SQLite。

主要指令：

```text
/start
/help
/language en|zh-TW
/cancel

/account_create <username> [device-limit]
/account_list
/account_enable <account-id>
/account_disable <account-id>
/account_delete <account-id>
/account_reset <account-id>
/account_devices <account-id> <limit>

/session_list <account-id>
/session_revoke <session-id>
/session_revoke_all <account-id>

/connection_add_s3 <name>
/connection_add_mysql <name>
/connection_add_postgres <name>
/connection_edit <connection-id> <name>
/connection_list
/connection_test <connection-id>
/connection_enable <connection-id>
/connection_disable <connection-id>
/connection_delete <connection-id>

/grant <account-id> <connection-id> <comma-separated-operations>
/grant_list <account-id>
/audit [limit]
```

connection add/edit 會進入逐步精靈。除了 slash commands，也可以從「Connections」inline 選單直接選擇新增 S3、MySQL 或 PostgreSQL 連線；兩種入口共用同一組欄位驗證與保存流程。輸入敏感欄位後，Bot 會盡力刪除該 incoming message。

### S3 精靈欄位

依序輸入：

1. S3 API endpoint URL。
2. Region；Cloudflare R2 通常為 `auto`。
3. Bucket。
4. 固定 base prefix；沒有時輸入 `-`。
5. Path-style：`on` 或 `off`。
6. Access key。
7. Secret key。

子帳號只能操作固定 bucket 與 base prefix。相對 object key 經服務端驗證後才交給 adapter，不能越過 connection 邊界。

### SQL 精靈欄位

依序輸入：

1. Host。
2. Port。
3. User。
4. Password。
5. Database。
6. MySQL TLS mode 或 PostgreSQL SSL mode。

SQL connection 固定 database。`query` 在 read-only transaction 中執行並受 timeout/row limit 保護；具副作用的 statement 必須使用獨立 `sql.exec` 權限。

### Operation grants

| Connection       | Operation    | 行為                   |
| ---------------- | ------------ | ---------------------- |
| S3               | `s3.read`    | List 與 Download。     |
| S3               | `s3.write`   | Upload。               |
| S3               | `s3.delete`  | Delete。               |
| MySQL/PostgreSQL | `sql.tables` | 列出 tables。          |
| MySQL/PostgreSQL | `sql.query`  | 執行 read-only query。 |
| MySQL/PostgreSQL | `sql.exec`   | 執行具副作用 SQL。     |

`/grant` 會驗證 operation 是否符合 connection kind。停權帳號、撤銷 session、停用 connection 或移除 grant 後，後續代理請求會立即被拒絕。

## REST API

API prefix 為 `/api/v1`。除 login/refresh 外，所有 endpoint 都需要 `Authorization: Bearer <access-token>`。

| Method   | Path                                       | 用途                                                      |
| -------- | ------------------------------------------ | --------------------------------------------------------- |
| `GET`    | `/healthz`                                 | Health check。                                            |
| `POST`   | `/api/v1/auth/login`                       | 使用 `username/password/deviceId` 登入。                  |
| `POST`   | `/api/v1/auth/refresh`                     | 使用 rotation `refreshToken/deviceId` 取得新 token pair。 |
| `POST`   | `/api/v1/auth/logout`                      | 撤銷目前 session。                                        |
| `GET`    | `/api/v1/resources`                        | 列出 enabled 且已指派的 connection summary，不含 secret。 |
| `GET`    | `/api/v1/resources/:id/s3/objects?prefix=` | 列出 object。                                             |
| `PUT`    | `/api/v1/resources/:id/s3/objects/*`       | `application/octet-stream` 串流上傳。                     |
| `GET`    | `/api/v1/resources/:id/s3/download/*`      | 串流下載。                                                |
| `DELETE` | `/api/v1/resources/:id/s3/objects/*`       | 刪除 object。                                             |
| `GET`    | `/api/v1/resources/:id/sql/tables`         | 列出 table。                                              |
| `POST`   | `/api/v1/resources/:id/sql/query`          | JSON `{statement, parameters?}` read-only query。         |
| `POST`   | `/api/v1/resources/:id/sql/exec`           | JSON `{statement, parameters?}` 執行具副作用 SQL。        |

API 錯誤使用 `{ "error": { "code": "...", "message": "..." } }`。resource response 只包含 connection ID、名稱、kind、enabled 與 operations。

## Windows GUI 遠端登入

1. 在本機設定或登入畫面選擇「登入校驗」。
2. 輸入完整 HTTP/HTTPS base URL、子帳號與密碼。
3. 登入成功後 GUI 只顯示已指派且 enabled 的 S3/SQL connection。
4. 各操作按鈕只在對應 grant 存在時顯示；服務端仍會再次授權，不能靠修改客戶端繞過。
5. 可用保存的 DPAPI refresh token 恢復 session；refresh 每次使用都會輪換。
6. 遠端 workspace 不顯示 SSH，也不提供 connection secret 編輯欄位。

密碼永不保存。`remote-preferences.json` 只保存 URL、帳號與隨機 device ID；refresh token 保存在既有 Windows DPAPI securestore 的獨立 namespace。

## 稽核與資料保存

SQLite 稽核包含時間、帳號/session/device/IP、operation、connection、成功/失敗、耗時，以及可用的 rows/bytes。SQL 僅保存 statement SHA-256 hash與 type；S3 不保存 object body。

預設保存 90 天。runtime 每日依 `AUDIT_RETENTION_DAYS` 清理；若需外部合規備份，應在不擴張敏感欄位的前提下另行匯出。

## 驗證

```powershell
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
npm audit --omit=dev --audit-level=high
```

測試使用 Node 內建 test runner、Fastify `inject` 與 in-memory SQLite，不需要真實 Telegram、S3 或 SQL 服務即可驗證核心契約。真實 adapter 另以可注入 client factory 驗證分頁、streaming、transaction、timeout 與 row limit。
