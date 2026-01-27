# 更新日誌 (CHANGELOG)

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
