# vacuumd 專案規格說明書
專案名稱

vacuumd – Roborock / Xiaomi 掃地機器人 LAN Controller 與自動化服務


## 設計目標
1. 底層封裝

- 封裝掃地機 IP 與 token

- 封裝 mirobo / miIO 底層操作

- 提供簡單可呼叫的 Python 方法 (start, pause, home, spot, fanspeed, status)

2. 安全與穩定

- 自動重試 (retry)

- timeout 處理

- state cache 避免多次查詢導致 UDP timeout

3. 操作簡單

-使用者只需要呼叫 controller 方法，不需打 CLI 長指令

- CLI 可提供快速測試與日常操作

4. 擴展性

- 支援 Scheduler（定時清掃 / 排程）

- 支援 REST API / MQTT / GNOME Tray / Home Assistant 整合

- 支援未來多台掃地機控制(選項)

5. 可維護

- IP、token 放入配置檔或環境變數

- 支援多機器人管理(選項)

## 資料夾結構
```
vacuumd/
 ├── controller.py       # VacuumController class 實作
 ├── config.yaml         # 配置掃地機 IP + token
 ├── cli.py              # CLI 工具: vacuumctl start/stop/status
 ├── service.py          # Systemd daemon template 範例
 ├── scheduler.py        # APScheduler 定時啟動範例
 └── test.py             # 使用與測試範例

```

## 結構設計
* controller.py
封裝底層掃地機指令，提供高層 API 給 Scheduler / CLI / REST API 呼叫
* config.yaml
保存掃地機 IP 與 token，可擴充多台掃地機配置
* cli.py
提供簡單 CLI：vacuumctl start / vacuumctl pause / vacuumctl home / vacuumctl status
* service.py
systemd service 範例，負責 daemon 常駐運行 vacuum controller，提供 logging 與 state cache
* scheduler.py
APScheduler 範例，用於定時啟動、暫停掃地機
* test.py
簡單測試與範例程式碼，方便驗證 controller 功能


## Controller Class 規格
```python
class VacuumController:
    """
    封裝 Roborock / Xiaomi 掃地機 LAN 控制

    Methods:
        start()         # 啟動掃地
        pause()         # 暫停掃地
        home()          # 回充
        spot()          # 定點掃地
        fanspeed(speed) # 調整吸力 (60~102)
        status()        # 查狀態 (回 dict)
    """

    def __init__(self, ip: str, token: str, retries: int = 3):
        # 初始化掃地機
        pass

    def _safe_call(self, fn, *args, **kwargs):
        # 重試呼叫底層 mirobo 函式
        pass

    def start(self):
        pass

    def pause(self):
        pass

    def home(self):
        pass

    def spot(self):
        pass

    def fanspeed(self, speed: int):
        pass

    def status(self) -> dict:
        """
        回傳掃地機狀態 dict:
        {
            "state": ...,
            "battery": ...,
            "fanspeed": ...,
            "cleaning_since": ...,
            "cleaned_area": ...,
            "error": ...
        }
        """
        pass

```

## 使用範例
```python
from controller import VacuumController

vac = VacuumController(ip="192.168.1.9", token="YOUR_TOKEN_HERE")

# 啟動掃地
vac.start()

# 暫停掃地
vac.pause()

# 回充
vac.home()

# Spot 定點清掃
vac.spot()

# 調整吸力
vac.fanspeed(90)

# 查狀態
status = vac.status()
print(status)

```

## 擴展性設計
* Scheduler Layer

  - APScheduler / Cron 排程 → 呼叫 VacuumController

  - 可依天氣、人員、電量、時間動態決策

* REST API Layer

  - Flask / FastAPI → 暴露 controller 方法給外部設備 / HA

* Systemd Service Layer

  - vacuumd.service → 常駐 daemon

  - 維護 state cache / retry / cooldown

* GUI / Tray

  - GNOME tray 或其他桌面 UI → 呼叫 controller API

* HA Integration

  - REST / MQTT → HA sensor & switch

## 小提醒 / 工程注意點
Parallel call：避免同時多個指令導致 UDP timeout

IP 固定：Router DHCP reservation

Token 保存：config.yaml 或環境變數，token 變更需重新配置

Cooldown：連續指令建議間隔 1~2 秒

重試機制：UDP 偶爾丟包時自動 retry

State cache：避免頻繁查詢導致狀態不穩

Fanspeed 范圍：60~102，避免超出上限

Spot / Zone 清掃：S5 舊機房間掃描支援有限，zone 座標需小心設定

## 禁止事項與邊界
1. 禁止直接修改掃地機內部地圖資料

  - 除非使用米家 App 進行地圖 / 禁區配置

  - 避免破壞地圖導致掃地機報錯

2. 禁止同時多次 start/home/pause 指令

  - UDP 控制層非可靠，可能造成掃地機無回應

3. 禁止在 token 過期或錯誤情況下操作

  - 避免永久失聯或 firmware mismatch

4. 禁止在網路不穩 / IP 變化下長時間 daemon 運行

  - 應加 retry / reconnect / cooldown 機制

5. 邊界條件

  * Fanspeed: 60~102

  * Battery < 20%：建議不啟動掃地

  * Spot 清掃半徑固定（S5 約 1~2m），不可超出地圖邊界

  * Scheduler 排程不得重疊，以免並行衝突


## 下一步工程建議

1. 建立底層 VacuumController class（完成）

2. 建立 config.yaml 多掃地機管理

3. CLI 包裝 controller 方法 → vacuumctl start/pause/home/status

4. 建立 service.py systemd daemon 範例 → 常駐運行

5. 建立 scheduler.py → APScheduler 定時任務範例

6. 後續擴展 → REST API / MQTT / GNOME tray / HA integration

## 交付標準 / LLM 可展開規範
* Python 3.11

* mirobo 套件作為底層控制

* 獨立 controller class，封裝 IP + token + retry

* CLI 可操作掃地機

* 可測試 / 可運行 / 可擴展

* 文件完整：README.md 說明 folder 結構與使用方式
