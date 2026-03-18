# TODO: ESP-MIAO 架構升級（Phases 1-4）

## Phase 1：智慧燈 Discovery 升級 [x]
## Phase 2：Server 動態建表 [x]
## Phase 3：Intent.py 改寫 [x]

## Phase 4：myxiaomi 對接 Discovery + MQTT Bridge
- [x] 加入 `paho-mqtt` 依賴並建立 `vacuumd/mqtt_bridge.py`（或等價檔案）
- [x] 設計 `mqtt_bridge`：訂閱 `home/vacuum_01/cmd`，`START` 觸發 `controller.start()`（若需 `full_clean()` 先新增方法），`DOCK` 觸發 `controller.home()`
- [x] `START` 成功後才寫入 `automation.active_runs`，失敗或拒絕不可寫入；`DOCK` 成功後移除對應 run
- [x] 開始前檢查 `status.battery` 並拒絕 `<20%` 的 `START`，錯誤訊息透過 MQTT 回應讓 esp-miao 顯示
- [x] FastAPI `startup_event` 建立 MQTT 連線（保存在 `app.state.mqtt_bridge`），`shutdown_event` 安全斷線
- [x] 啟動時向 `home/discovery` 發佈 payload（含 `device_id/device_type/aliases/action_keywords/commands/control_topic`），建議 `retain=true`
- [x] 新增 `MQTT_HOST` / `MQTT_PORT` / `MQTT_AUTH_USER` / `MQTT_AUTH_PASSWORD` 環境變數讀取並在說明文件與 `.env` 範例中註明
- [x] 若支援 TLS 或 keepalive，補上 `MQTT_TLS` / `MQTT_KEEPALIVE` 的預設與說明
- [x] MQTT 連線失敗（例如認證錯誤）要 log 警告並跳過 discovery 发布，但不應阻塞 FastAPI 或其他核心服務啟動
- [ ] 撰寫測試 / 手動驗證流程：Discovery payload 格式、MQTT 指令到 VacuumController、low battery 拒絕、active_runs 出/入、fallback guard 略過
