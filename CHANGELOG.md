# 更新日誌 (CHANGELOG)

### [0.3.8] - 2026-03-08

### 新增
- **每小時 31 分備援守門機制**：新增 fallback guard 排程（預設 `31 * * * *`），在偵測到機器人清掃中時，經過二次確認後自動下達回充指令。

### 優化
- **雙階段狀態確認**：fallback guard 會先檢查一次狀態，再等待 `fallback_guard_confirm_seconds` 後做第二次確認，降低誤判觸發機率。
- **與快取協調**：啟動時會自動確保確認秒數至少大於 `cache_ttl`，避免二次確認讀到同一筆 TTL 快取資料。
- **長任務保護**：fallback guard 僅處理「清掃時長在門檻內」的任務，且遇到本地 `active_runs` 會直接略過，避免誤停 myxiaomi 全屋等長時清掃。
- **排程列表去雜訊**：`list_jobs()` 會略過系統內部任務（run reconcile 與 fallback guard），避免干擾使用者排程檢視。

### 配置
- `server` 區塊新增：
  - `fallback_guard_enabled`（預設 `true`）
  - `fallback_guard_cron`（預設 `"31 * * * *"`）
  - `fallback_guard_confirm_seconds`（預設 `6`）
  - `fallback_guard_recent_cleaning_minutes`（預設 `10`）

### [0.3.7] - 2026-03-07

### 優化
- **LAN-First 網路策略收斂**：確認本地 Fake Cloud 架構以「精準 DNS 攔截」為主，不再依賴攔截整個 Xiaomi 網域。
- **部署路徑簡化**：在 Router DNS 正確指向 RPi `dnsmasq` 的前提下，`iptables DNAT` 由必要條件降為可選備援。

### 修復
- **DNS storm 根因排除**：移除過度寬泛的 DNS spoof（如 `mi.com`/`xiaomi.com` 全網域攔截）後，解決 vacuum Cloud retry loop 造成的高頻 DNS 查詢與網路風暴。

### 文件
- 新增並整理 2026-03-07 技術紀錄，完整記錄 DNS storm 的根因、修復策略與最終穩定拓樸。
- README 補充「DNS 設定重點」，明確規範僅攔截 `ot.io.mi.com` / `ott.io.mi.com`（含區域子網域）與 Router DNS 轉送路徑。
- 將 `setiptables_vacuum_fix.sh`、`unsetiptables_vacuum_fix.sh` 調整為本地實驗腳本，不再納入版本追蹤。

### [0.3.6] - 2026-03-06

### 新增
- **排程歷史資料模型**：新增 `RunEvent` 與 `RunRecord`，建立排程執行事件與單次清掃結果的結構化資料基礎。
- **歷史儲存層**：新增 `HistoryStore`，使用本地 `data/cleaning_history.jsonl` 儲存事件與 run 紀錄，支援 `list_runs()` 與 `aggregate_stats()`。
- **歷史統計 API**：
  - `GET /v1/history/runs` — 查詢排程歷史紀錄（支援 `device_id`、`task_id`、`limit`、時間區間）。
  - `GET /v1/history/stats` — 查詢累計統計與 `zone_breakdown` 分區統計。
- **Dashboard 歷史視覺化**：新增「排程歷史與清掃統計」區塊，顯示最近 run、累計統計卡片、分區統計與估算標記。

### 優化
- **排程生命週期追蹤**：`AutomationEngine` 新增 `active_runs`，於排程啟動時記錄 baseline（電量、面積、時間）。
- **完成判定穩定化**：新增背景輪詢 `_reconcile_active_runs()`，採「連續 2 次非 Cleaning/Returning」才判定完成，並對 `Offline/Busy` 延後判定，降低誤判。
- **重啟恢復**：服務啟動時會補記遺留 run 為 `unknown_end`，避免歷史資料靜默遺失。

### 修復
- 修正專案執行期歷史檔案管理：新增 `.gitignore` 規則忽略 `data/cleaning_history.jsonl`，避免將運行資料誤納入版本控制。

### [0.3.5] - 2026-03-05

### 新增
- **排程修改功能**：Dashbaord 列表新增「修改」按鈕，支援動態調整現有排程的 Cron、分區與時長，無需刪除重建。
- **原子性檔案儲存**：`save_schedules` 導入原子性寫入機制（暫存檔 + `fsync` + `replace`），防止配置檔案因非預期中斷而損毀。
- 排程列表補齊「清掃區域」欄位，自動將 Zone ID 轉換為易讀名稱。

### 優化
- **UX 用語親民化**：將介面與 API 回應中的技術用語「持久化」全面替換為「儲存」，提升一般使用者體驗。
- **介面佈局一致性**：移除排程區段的寬度限制，確保與裝置卡片區段在各種螢幕尺寸下皆向左對齊。
- **時間格式優化**：日期與時間字串間增加間距，並移除冗餘的 UTC 顯示，介面更為清爽。
- 儲存流程加入 `0.5s` 安全容許時間，確保作業系統檔案系統穩定。

### [0.3.4] - 2026-03-05

### 新增
- **使用者時區支援**：`config.yaml` 新增 `server.timezone` 設定（IANA 格式，如 `"Asia/Taipei"`），cron 排程時間依此時區解讀，內部邏輯統一使用 UTC。
- **排程管理 REST API**：
  - `GET /v1/schedules` — 列出所有排程任務及下次觸發時間（含 UTC 與使用者時區）。
  - `POST /v1/schedules` — 動態新增排程任務（自動驗證 device_id 存在性）。
  - `DELETE /v1/schedules/{task_id}` — 移除指定排程。
- 排程引擎新增 `remove_cleaning_job()` 與 `list_jobs()` 方法，支援動態排程管理。
- `Settings` 新增 `get_user_tz()` 便利函式，回傳 `ZoneInfo` 物件。

### 優化
- **全域日誌加入 UTC ISO8601 時間戳**：所有模組 logger 輸出自動帶 `%Y-%m-%dT%H:%M:%S` 格式 UTC 時間。
- 排程引擎所有關鍵日誌同時印出 UTC 與使用者當地時間，方便除錯與監控。
- `config.yaml` 排程備註標明時區依據，避免 cron 時間被誤讀為 UTC。
- `ScheduledTask` 模型補齊 `zones` 欄位，與引擎實際功能對齊。

### [0.3.3] - 2026-03-04

### 新增
- 根據 `AGENTS.md` 規範補強開發者合約，明確「正確性優先」與「繁體中文」開發原則。
- 補齊 `VacuumController` 中缺失的 `spot()` 定點清掃方法，完全對齊 `SPEC.md` 規格。
- 新增 `fanspeed()` 方法並實作 SPEC 要求之安全範圍檢查 (60-102)。
- **實作分區排程功能**：
  - 排程設定支援 `zones` 參數，可指定分區 ID 進行局部清掃。
  - 當 `zones` 為空時執行全屋清掃，指定時僅清掃指定分區。
  - 新增 `zone_discovery.py` 偵錯腳本，協助使用者找出 Zone ID 對應關係。
  - 已驗證 Roborock S5 Zone ID 對應：8(全屋)/16(主臥室)/17(客廳1)/18(次臥室)/19(客廳2)/20(書房)/21(廚房)。

### 修復
- 修復 `python-miio` 升級導致的匯入路徑錯誤 (`miio` -> `miio.integrations.vacuum`)。
- 修正 `VacuumController` 初始化參數的型別提示與預設值錯誤 (LSP 修正)。

### [0.3.2] - 2026-03-02

### 新增
- 支援從 `config.yaml` 的 `schedules` 載入多筆排程任務，啟動時自動註冊。
- 排程支援標準 5 欄 crontab（`分 時 日 月 週`），可設定平日/特定日期等規則。
- Web Dashboard 介面文案完成繁體中文化，並新增狀態字串中文轉換顯示。

### 優化
- `start-server.sh` 強化啟動流程：自動載入 `.env`、檢查必要環境變數、固定使用 `uv` 與專案 `.venv` Python。
- 新增 `UV_CACHE_DIR` 預設路徑，降低不同執行環境下的快取權限問題。
- 啟動日誌改為顯示實際載入的排程筆數，便於排程配置驗證。

### 修復
- 修正 API/Controller 介面落差：補齊 `segment_clean`、`zoned_clean`、`get_room_mapping`。
- 修正 `status()` 在 Unreachable 狀態下的短期快取邏輯，避免不合法 `TTLCache` 用法。
- 修正 mutable default 風險（`room_mapping`、`params`），避免跨請求/實例共享資料。
- 設定檔 token 改為支援 `token_env` 注入，避免明碼 token 外洩風險。

### [0.3.1] - 2026-01-28

### 新增
- 整合 `micloudfaker` 理念，實作 `CloudFaker` 控制器模組。內建 UDP/TCP 8053 伺服器，模擬小米雲端握手響應。
- 更新 `setiptables_vacuum_fix.sh` (V4)，新增自動檢測 usb0 狀態並實施「流量截流至 Faker」的策略。
- 支援對 `*.io.mi.com` 的 TCP 80 與 UDP 8053 流量攔截與重定向。

### 優化
- 強化斷網防休眠策略：結合「Fake Cloud 響應」與「主動 Hello 喚醒」，雙層保護掃地機 LAN 控制權。

### [0.3.0] - 2026-01-28

### 新增
- 實作「斷網連線修復」腳本 `setiptables_vacuum_fix.sh`，專為 RPi4 網關環境設計，包含透明 DNS 攔截與 STUN 劫持。
- 在 `VacuumController` 中增加「主動喚醒機制」，針對斷網時掃地機 UDP 埠口休眠問題進行強制握手。
- 為 `VacuumState` 增加 `is_reachable` 狀態標記，提供更精確的 LAN 連線診斷。
- 下載所有前端 CDN 資源 (Tailwind, Alpine.js) 至本機 `static/js`，支援完全無網路環境下的儀表板顯示。

### 優化
- 調整底層通訊超時 (Timeout) 從預設值提升至 5 秒，增強在機器人 CPU 忙碌時的耐受力。
- 改善 UI 儀表板，增加設備離線 (Unreachable) 的視覺警示與灰色標記。

### 修復
- 修正 `RoborockVacuum` 初始化時無法接受 timeout 參數的 TypeError。
- 補回在先前重構中遺失的 `_safe_call` 裝飾器封裝方法。

### [0.2.1] - 2026-01-27

### 新增
- 實作地圖分區與房間清掃支援 (`segment_clean`, `zoned_clean`)。
- 增加手動房間映射功能 (`room_mapping`)，解決舊版 Roborock S5 韌體無法在 App 中命名房間的限制。
- 新增 `debug_segments.py` 與 `inspect_robot.py` 偵錯工具。

### 優化
- 強化 API 相容性：自動偵測並適應 `python-miio` 不同版本間的方法命名差異 (如 `app_zoned_clean` vs `zoned_clean`)。
- 改善房間發現邏輯：當設備不支援命名房間時，自動回退 (Fallback) 至獲取原始分區狀態。

## [0.2.0] - 2026-01-27

### 新增
- 實作完整的專案架構目錄 (model, controller, api, view, cli, config, scheduler)。
- 建立基於 FastAPI 的 RESTful API 服務，支援多設備管理。
- 實作智慧排程引擎 (Automation Engine)，支援 cron 語法與任務衝突檢查。
- 建立現代化網頁儀表板，支援即時狀態監控與手動控制。
- 實作 vacuumctl 命令列工具，提供美觀的表格化輸出。
- 增加 start-server.sh 腳本，簡化伺服器啟動流程並自動處理埠號衝突。

### 優化
- 強化控制層穩定性：導入 tenacity 指數退避重試與狀態快取機制。
- 規範化時間處理：全面採用時區感知的 datetime 物件與 Unix Timestamp，避免使用已棄用的函式。
- 強化模型校驗：使用 Pydantic 對設備配置與機器人狀態進行嚴謹定義。

### 修復
- 修復 S5 機型在 python-miio 中缺少 is_on_charger 屬性導致的解析異常。
- 修正模組導入路徑問題，確保 uv run 環境下運作正常。

## [0.1.0] - 初期版本
- 專案規格說明 (SPEC.md) 制定。
- 基礎 miIO 通訊實驗與指令測試。
