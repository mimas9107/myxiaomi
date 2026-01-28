# vacuumd 專案說明書

版本：0.2.0

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
   - 衝突檢測：當任務重疊時，會根據預計執行時間與當前硬體狀態決定是否跳過任務。
   - 電量守護：啟動排程前自動檢查電量，低於 20% 則不啟動。
   - 時間規範：內部邏輯全面採用時區感知（Timezone-aware）的 UTC 時間與 Unix Timestamp。

## 安裝與啟動

### 環境需求
- Python 3.11 或以上版本
- uv 套件管理工具

### 啟動伺服器
執行以下腳本即可自動釋放埠號並啟動服務：
```bash
bash start-server.sh
```

### 房間與分區管理
針對部分 Roborock S5 舊版韌體無法在 App 命名房間的問題，系統支援手動配置 `room_mapping`。
- **取得房間列表**: `GET /v1/devices/{id}/rooms`
- **執行分區清掃**: 支援 `segment_clean` 與 `zoned_clean` 指令，並具備自動向下相容的 API 調用邏輯。

### 命令列工具使用
uv run python vacuumd/cli/main.py status

## 排程邏輯說明
當排程任務觸發時，系統會執行以下檢查：
1. 硬體狀態：若機器人正處於 Cleaning 或 Returning 狀態，將略過新任務。
2. 預計時長：若當前時間仍處於上一個任務的預計結束時間內，系統將判定為衝突並跳過。
3. 剩餘電量：若電量不足以支撐清掃任務，系統將主動攔截指令。
