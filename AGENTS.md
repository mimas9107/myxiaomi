# vacuumd 專案開發者合約 (AGENTS.md)

本文件定義了參與 vacuumd 專案開發時必須遵守的核心原則與技術規範。

## 1. 核心原則 (Core Contract)
- **正確性第一 (Correctness-First)**：正確性 > 可追溯性 > 清晰度 > 速度。嚴禁虛構 API、檔案或事實。若資訊不明，必須停止並詢問。
- **繁體中文優先**：除原始代碼或第三方庫內容外，所有註釋、文件 (README/SPEC/CHANGELOG/AGENTS) 及 UI 文案必須使用**繁體中文**。
- **禁止回退**：除非明確要求，否則禁止撤銷已實現的功能或修復。

## 2. 專案技術規範 (Technical Mandates)
- **斷網優先設計 (LAN-First Design)**：
  - 確保系統在完全無外網環境下仍可運作。
  - 嚴禁引入外部 CDN 資源，所有 JS/CSS 必須下載至 `static/js`。
  - 修改通訊邏輯時，不可破壞 `CloudFaker` 模擬與 `IPTables` 流量截流邏輯。
- **通訊穩定性與快取**：
  - 底層 miIO 調用必須封裝於 `_safe_call` 或 `_safe_call_any` 中。
  - 必須設定底層 Timeout 為 5 秒，並保留 `tenacity` 的指數退避重試機制。
  - 狀態查詢必須使用 `TTLCache`，避免 UDP 請求過於頻繁導致機器人 CPU 忙碌或休眠。
  - 偵測到通訊異常時，應優先嘗試發送 UDP Hello 或 `miIO.info` 進行主動喚醒。
- **排程與自動化**：
  - 所有時間處理必須採用時區感知 (Timezone-aware) 的 **UTC 時間**。
  - 啟動清掃任務前，必須檢查「電量守護」邏輯（電量 < 20% 應攔截指令）。
  - 必須實施「任務衝突檢測」，避免多個排程或手動指令同時執行。
- **安全性與配置**：
  - 嚴禁將 `token` 明碼寫入 `config.yaml` 或提交至 Git。
  - 應優先支持 `token_env` 從環境變數讀取敏感資訊。
  - 使用者應透過 `start-server.sh` 啟動服務，確保自動載入 `.env`。

## 3. 執行協議 (Execution Protocol)
- **環境一致性**：執行測試或啟動服務時，必須強制使用 `uv run` 並指向專案內的 `.venv` Python。
- **修改前檢查**：
  - 使用 `grep -n` 定位精確行號。
  - 涉及核心控制邏輯時，先閱讀 `SPEC.md` 確認符合設計規格。
- **原子性變更**：
  - 每次編輯檔案後應立即驗證，不進行批次盲目修改。
  - 完成功能開發後，必須同步更新 `CHANGELOG.md` 的對應版本記錄。

## 4. 目錄職責
- `model/`: 強型別 Pydantic 資料模型。
- `controller/`: 封裝 miIO 穩定通訊與 CloudFaker。
- `api/`: FastAPI REST 接口與路徑。
- `scheduler/`: 時區感知的智慧排程引擎。
- `view/`: 純本地資源的 Web Dashboard。
- `cli/`: `vacuumctl` 命令列工具。
