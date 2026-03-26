# PFX 轉換 — AIA 自動補齊 Intermediate 憑證

**日期**: 2026-03-26
**狀態**: 設計完成，待實作

## 摘要

當 PFX 檔案缺少 intermediate 憑證時，提供手動觸發的 AIA (Authority Information Access) 下載功能，遞迴追蹤憑證鏈直到 root CA，並新增 fullchain 輸出檔案。

## 需求

1. 使用者載入 PFX 並轉換後，可手動按「補齊憑證鏈」按鈕觸發 AIA 下載
2. 遞迴追蹤 AIA 擴展中的 CA Issuers URL，從 leaf 一路往上直到 self-signed (root) 或無 AIA
3. 提供「包含 Root CA」checkbox，讓使用者決定 fullchain 是否包含 root（預設不勾選）
4. 下載失敗時靜默降級 — 有抓到多少就用多少，在 GUI 資訊區塊提示錯誤
5. 儲存時新增 `_fullchain.crt` 輸出（leaf + intermediates，依 checkbox 可含 root）

## 架構

### 新增模組：`src/certificate/aia.py`

獨立模組，負責 AIA 解析與憑證下載。不引入額外依賴，使用 `urllib.request` 處理 HTTP。

#### 資料結構

```python
@dataclass(frozen=True)
class AiaResult:
    certificates: list[x509.Certificate]  # 下載到的 intermediate (+ 可能的 root)
    errors: list[str]                      # 過程中的錯誤訊息
    root_found: bool                       # 是否追蹤到 self-signed root
```

#### 核心函式

```python
def fetch_intermediate_chain(
    cert: x509.Certificate,
    existing_certs: list[x509.Certificate] | None = None,
    max_depth: int = 10,
    timeout: int = 10,
) -> AiaResult
```

- 輸入：leaf 憑證，以及 PFX 內已有的 additional_certs（用於去重）
- 行為：解析 AIA → 下載 issuer → 遞迴追蹤 → 到 self-signed 或無 AIA 時停止
- 防護：最大遞迴深度 10 層，單次 HTTP timeout 10 秒
- 去重：下載到的憑證與 `existing_certs` 做 SHA-256 fingerprint 比對

```python
def get_aia_ca_issuer_urls(cert: x509.Certificate) -> list[str]
```

- 從 AIA 擴展提取 caIssuers URL
- 無 AIA 擴展時回傳空 list

### GUI 變更（`gui.py` PFX tab）

#### 新增 UI 元素

1. **「補齊憑證鏈」按鈕** — 在「轉換」按鈕旁邊，初始為 disabled，轉換成功後啟用
2. **「包含 Root CA」checkbox** — 控制 fullchain 輸出是否包含 root，預設不勾選

#### 互動流程

1. 載入 PFX → 輸入密碼 → 按「轉換」→ 顯示憑證資訊（現有行為不變）
2. 轉換成功後，「補齊憑證鏈」按鈕啟用
3. 按下「補齊憑證鏈」→ 呼叫 `fetch_intermediate_chain()` → 更新資訊區塊
4. 資訊區塊新增段落：
   - 成功：`═══ AIA 補齊結果 ═══` + 每張下載到的 intermediate 資訊
   - 部分失敗：同上 + `⚠ 部分憑證無法取得: <錯誤訊息>`
   - 完全失敗：`⚠ 無法透過 AIA 取得 intermediate 憑證: <原因>`

#### 儲存輸出

轉換 + 補齊後，儲存時產生：

| 檔案 | 內容 | 條件 |
|------|------|------|
| `<name>.crt` | 主憑證 | 一律產生（不變） |
| `<name>.key` | 私鑰 | 有私鑰時產生（不變） |
| `<name>_chain.crt` | PFX 原有附加憑證 + AIA 下載的 intermediate，按鏈順序排列（leaf 的 issuer 在前，往 root 方向排） | 有附加/下載憑證時產生 |
| `<name>_fullchain.crt` | leaf + 所有 intermediate（依 checkbox 可含 root） | **新增**，有按過「補齊憑證鏈」時產生 |

### 邊界情況與去重

- PFX 已含 intermediate → 用 `build_chain()` 排序已有憑證，從鏈中最上層的 intermediate（最接近 root 的那張）開始 AIA 追蹤，fingerprint 去重避免重複
- AIA URL 為 `http://`（非 https）→ 正常處理，CA 的 AIA 常用 HTTP
- AIA 回傳 DER 格式 → 自動偵測並解析（大多數 CA 的 AIA 回傳 DER）
- 未按「補齊憑證鏈」直接儲存 → 行為與現在一致，不產生 fullchain

### 錯誤處理

全部採靜默降級策略：

| 情境 | 處理方式 |
|------|----------|
| 憑證無 AIA 擴展 | `errors` 記錄，`certificates` 為空 |
| URL 無法存取 / timeout | 記錄錯誤，繼續處理已下載部分 |
| 下載資料非合法憑證 | 跳過該 URL，記錄錯誤 |
| 遞迴深度超過 10 | 停止追蹤，記錄警告 |

## 測試

### `tests/test_aia.py`

- `get_aia_ca_issuer_urls()` — 有 AIA / 無 AIA 擴展的憑證
- `fetch_intermediate_chain()` — mock `urllib.request.urlopen`：
  - 正常多層遞迴下載（DER 格式）
  - 部分 URL 失敗的降級行為
  - 最大遞迴深度限制
  - 非法資料的跳過處理
- 去重邏輯 — 已有的 intermediate 不重複
- DER vs PEM 格式自動偵測

不測 GUI，與現有慣例一致。

## 異動檔案

| 檔案 | 變更類型 |
|------|----------|
| `src/certificate/aia.py` | 新增 |
| `src/certificate/gui.py` | 修改（PFX tab 新增按鈕、checkbox、輸出邏輯） |
| `tests/test_aia.py` | 新增 |
