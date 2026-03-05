# vacuumd 專案說明書

版本：0.3.5

## 專案簡介
vacuumd 是一個針對 Roborock / Xiaomi 掃地機器人開發的家庭內網（LAN）控制器。本專案透過封裝底層 miIO 通訊協議，提供具備高可靠性、狀態快取以及智慧排程功能的控制系統。

## 系統架構
專案採用模組化設計，各層級職責分明：

1. model: 使用 Pydantic 定義強型別資料模型，統一機器人狀態與設備資訊格式。
2. controller: 核心控制層，整合 tenacity 重試機制與 cachetools 狀態快取，優化 UDP 通訊穩定性。
3. api: 基於 FastAPI 的 RESTful 接口，提供外部整合與前端呼叫。
4. view: 基於 Tailwind CSS 與 Alpine.js 的輕量化網頁儀表板。
5. cli: 基於 Typer 的命令列工具 vacuumctl，方便終端機操作。
6. config: 採用 YAML 格式進行多設備配置管理。
7. scheduler: 智慧自動化排程引擎，具備任務衝突檢測與電量守護邏輯。

## 核心特性
1. 穩定通訊：實作指數退避重試機制，並手動調整底層 Timeout 至 5s，解決內網 UDP 丟包與斷網延遲問題。
2. 斷網容錯 (LAN-First Design)：
   - MiCloud Faker (整合自 micloudfaker 理念)：內建微型小米雲端模擬器，響應機器的 HELO 與 HTTP 請求，徹底防止掃地機因斷網進入「離線休眠」或頻繁重啟 Wi-Fi。
   - 整合 RPi4 網關規則：透過 IPTables 透明導向技術，在斷網時自動將雲端流量截流至本地 Faker。
   - 主動喚醒機制：偵測到通訊異常時發送 `miIO.info` 喚醒封包，雙重保障 UDP 埠口存活。
   - 離線優先顯示：Web Dashboard 整合本地化資源，並提供連線連通性 (`is_reachable`) 視覺化標記。
3. 狀態快取：設定 TTL 快取，避免頻繁查詢導致機器人 CPU 過載。
3. 智慧排程：
   - **視覺化管理**：透過 Web Dashboard 輕鬆新增、修改或刪除排程，支援區域多選。
   - **時區感知**：Cron 時間依據 `server.timezone` 全域設定解讀，貼近使用者作息。
   - **衝突檢測**：自動判定任務重疊並根據硬體狀態決定是否執行。
   - **電量守護**：啟動前檢查電量，低於 20% 自動攔截。

## 近期技術更新 (0.3.5)
- **排程管理介面升級**：實作「修改排程」功能，優化分區顯示與時間格式，移除冗餘 UTC 欄位。
- **原子性儲存機制**：配置檔寫入導入 `tempfile` + `fsync` 流程，並加入安全容許時間確保穩定。
- **使用者時區支援**：新增 `server.timezone` 設定，讓排程時間 (Cron) 依當地時間表達。
- **UX 用語優化**：將介面與 API 中的技術詞彙「持久化」替換為「儲存」，提升操作直覺度。
- 補齊 `VacuumController` API 以完全符合 `SPEC.md` 要求。
- Web Dashboard 佈局優化，確保各區段在大螢幕下對齊一致。

## 安裝與啟動

### 環境需求
- Python 3.11 或以上版本
- uv 套件管理工具

### 啟動伺服器
執行以下腳本即可自動釋放埠號並啟動服務：
```bash
./start-server.sh
```

`start-server.sh` 會依序執行：
- 載入專案根目錄 `.env`（若存在）
- 檢查 `VACUUM_ROBOT_S5_TOKEN`
- 使用 `uv run --python .venv/bin/python` 啟動 Uvicorn

### 安全設定（Token）
建議改用環境變數注入 token，避免明碼寫入設定檔：

```yaml
devices:
  - id: "robot_s5"
    name: "Living Room Vacuum"
    ip: "192.168.1.9"
    token_env: "VACUUM_ROBOT_S5_TOKEN"
```

若同時設定 `token` 與 `token_env`，系統會優先使用 `token`。

### 房間與分區管理
針對部分 Roborock S5 舊版韌體無法在 App 命名房間的問題，系統支援手動配置 `room_mapping`。
- **取得房間列表**: `GET /v1/devices/{id}/rooms`
- **執行分區清掃**: 支援 `segment_clean` 與 `zoned_clean` 指令，並具備自動向下相容的 API 調用邏輯。

### Zone ID 探索工具
由於 S5 舊韌體限制，無法自動讀取分區 ID。專案提供 `zone_discovery.py` 工具協助建立對應關係。

#### 使用方式
1. **偵測當前分區**：
   在米家 APP 啟動分區清掃的同時，執行：
   ```bash
   uv run python zone_discovery.py
   ```

2. **測試特定 Zone ID**：
   等待機器人回充後，執行：
   ```bash
   uv run python zone_discovery.py --test 16
   ```
   觀察機器人前往的區域，重複測試所有 ID (1-21) 以建立對應表。

#### 已驗證之 Zone ID 對應 (Roborock S5)
| Zone ID | 區域名稱 |
| :--- | :--- |
| 8 | 全屋 |
| 16 | 主臥室 |
| 17 | 客廳1 |
| 18 | 次臥室 |
| 19 | 客廳2 |
| 20 | 書房 |
| 21 | 廚房 |

### 命令列工具使用
uv run python vacuumd/cli/main.py status

### 排程時區
預設情況下，所有排程時間 (Cron) 將依據 `config.yaml` 中 `server.timezone` 的設定來解讀。例如設定為 `Asia/Taipei` 後，`0 13 * * *` 即代表台北時間下午一點。內部邏輯仍統一使用時區感知（Timezone-aware）的 UTC 時間。

### 排程設定（config.yaml）
可在 `schedules` 新增多筆任務，支援標準 5 欄 crontab：

```yaml
schedules:
  # 全屋清掃範例
  - task_id: "daily_1300"
    device_id: "robot_s5"
    cron: "0 13 * * *"
    est_duration: 40
    enabled: true

  # 分區清掃範例（僅清掃指定 zone）
  - task_id: "kitchen_night"
    device_id: "robot_s5"
    cron: "0 21 * * *"
    est_duration: 15
    enabled: false
    zones: [21]  # 只掃廚房

  # 多區域清掃範例
  - task_id: "bedroom_morning"
    device_id: "robot_s5"
    cron: "30 8 * * 1-5"
    est_duration: 20
    enabled: false
    zones: [16, 18]  # 清掃主臥室 + 次臥室
```

欄位說明：
- `task_id`: 任務唯一識別碼
- `device_id`: 對應 `devices` 中的設備 ID
- `cron`: `分 時 日 月 週`
- `est_duration`: 預估清掃分鐘數（用於衝突判斷）
- `enabled`: 是否啟用該任務
- `zones`: 分區 ID 列表（可參考上表），若省略或為空則執行全屋清掃
