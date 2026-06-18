---
name:          "AGENTS.md"
description:   "vacuumd 專案開發者合約 — 斷網優先設計與 miIO 通訊規範"
created_date:  "2026/05/29 13:25:00"
modified_date: "2026/06/18 10:35:00"
project_version: "1.0.0"
document_version: "1.1.0"
agent_sign: ['human/mimas', 'gemini cli/gemini-cli']
---

# vacuumd 專案開發者合約 (AGENTS.md)

本文件定義 vacuumd 專案的核心原則與技術規範。Agent 必須同時遵循工作區全域規範 (`../AGENTS.md`)。

## 1. 核心原則 (Core Contract)
- **正確性第一 (Correctness-First)**：正確性 > 可追溯性 > 清晰度 > 速度。
- **繁體中文優先**：所有註釋、文件及 UI 文案必須使用繁體中文。
- **禁止回退**：除非明確要求，否則禁止撤銷已實現的功能或修復。

## 2. 專案技術規範 (Technical Mandates)
- **斷網優先設計 (LAN-First Design)**：嚴禁引入外部 CDN，JS/CSS 必須下載至本地。
- **通訊穩定性 (miIO)**：調用必須封裝於 `_safe_call`，設定 5 秒 Timeout 與 `tenacity` 指數退避。
- **排程與自動化**：採用時區感知 (Timezone-aware) 的 **UTC 時間**。
- **安全守護**：電量 < 20% 應攔截清掃指令；禁止將 `token` 明碼寫入配置。

## 3. 執行協議 (Execution Protocol)
- **環境一致性**：強制使用 `uv run` 指向專案內的 `.venv`。
- **開發日誌規約**：必須依照 `./develop_journal/<YYYY-MM-DD/>` 路徑維護 `PLAN.md` 與 `TODO.md`。

## 4. 目錄職責 (Directory Roles)
- `model/`: Pydantic 資料模型。
- `controller/`: miIO 通訊與 CloudFaker 封裝。
- `api/`: FastAPI REST 接口。
- `scheduler/`: 時區感知排程引擎。

---
*註：本文件專注於 vacuumd 業務與通訊邏輯，通用環境指令請查閱全域規範。*
