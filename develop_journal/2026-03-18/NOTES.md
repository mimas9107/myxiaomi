# NOTES: ESP-MIAO 架構升級（Phases 1-4）

## 1. Phase 1-3 整合重點回顧
- **MQTT Buffer Size**：Discovery JSON 約 400 bytes，超過 `PubSubClient` 預設緩衝。
  - **處置**：Arduino 端需設定 `mqttClient.setBufferSize(1024)`。
- **Server NameError**：`connection.py` 使用 `ACTION_KEYWORDS` 但未匯入。
  - **處置**：補上 import。

## 2. 已驗證成效
- **多裝置共存**：ESP32 Light / Fan 同時註冊成功。
- **專屬關鍵字命中**：風扇 / 燈的關鍵字不再互相干擾。
- **邏輯更可預期**：移除掃地機硬編碼後，解析流程更容易除錯。

## 3. Phase 4 對接提醒（依 NOTIFY.md）
- Discovery 必須送到 `home/discovery`。
- Discovery Payload **必須包含** `action_keywords`，因 esp-miao 已移除 vacuum 類型硬編碼預設啟動邏輯。
- `control_topic` 必須對應 `home/vacuum_01/cmd`，並支援 `START` / `DOCK`。

## 4. Phase 4 設計注意事項
- 語音觸發需寫入 `active_runs`，讓 fallback guard（每小時 31 分）可辨識並略過守門。
- 電量守護（< 20% 拒絕啟動）與排程衝突檢測必須沿用現有邏輯。
- esp-miao 不可再直接透過 HTTP 操作 myxiaomi，需以 MQTT 對接。
- 啟動位置確定採 **FastAPI lifespan**，`start-server.sh` 僅作為啟動 server 的命令腳本。

## 5. Phase 4 實測紀錄（2026-03-18）
- myxiaomi 啟動時 MQTT 連線成功，已訂閱 `home/vacuum_01/cmd`。
- 語音指令「小貓回家」可成功觸發回充。
- 目前 esp-miao 仍使用 HTTP dispatch，需切換為 MQTT 後再補齊 discovery / status topic 驗證流程。
