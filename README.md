# 憑證工具

跨平台憑證管理工具，提供圖形化介面，支援 CSR 產生、憑證鏈驗證、PFX 轉換、自簽憑證產生等功能。

## 功能總覽

| Tab | 功能 | 說明 |
|-----|------|------|
| 產生 CSR | CSR 產生 | 填寫 Subject 欄位與 SAN，產生 CSR 與私鑰 |
| 檢視 CSR | CSR 解碼 | 載入或貼上 CSR，檢視 Subject、SAN、公鑰資訊 |
| 驗證憑證鏈 | 憑證鏈驗證 | 驗證憑證鏈的順序、簽章、有效期是否正確 |
| 排序憑證鏈 | 憑證鏈排序 | 將無序憑證自動排成 leaf → root 的正確順序 |
| PFX 轉換 | PFX → PEM | 將 PFX/P12 檔案轉換為 CRT + KEY（PEM 格式） |
| 自簽憑證 | 自簽憑證產生 | 產生自簽憑證，支援 SAN、CA 模式、自訂有效天數 |

## 安裝與執行

### 環境需求

- Python 3.10 以上
- [uv](https://docs.astral.sh/uv/) 套件管理器

### 從原始碼執行

```bash
# 安裝相依套件
uv sync

# 啟動 GUI
uv run certificate
```

### 下載預建版本

**macOS** — 透過 [Homebrew](https://brew.sh/) 安裝：

```bash
brew tap josephjsf2/tap
brew install --cask josephjsf2/tap/certificate
```

**Windows** — 至 [Releases](https://github.com/josephjsf2/certificate/releases) 頁面下載 `certificate-windows.zip`，解壓後執行 `CSR工具.exe`。

## 使用說明

### 1. 產生 CSR

用於向憑證機構（CA）申請憑證時產生 CSR 檔案。

1. 填寫 **通用名稱 (CN)**（必填），例如 `example.com`
2. 視需要填寫組織 (O)、部門 (OU)、國家代碼 (C) 等欄位
3. 選擇 **金鑰長度**（2048 或 4096）
4. 如需 SAN，在文字區域中每行輸入一筆，格式為：
   ```
   DNS:example.com
   DNS:www.example.com
   IP:192.168.1.1
   ```
5. 點擊「**產生 CSR**」，選擇儲存位置
6. 產出檔案：`{CN}.csr`（CSR）與 `{CN}.key`（私鑰）

### 2. 檢視 CSR

用於檢視 CSR 檔案的內容。

1. 點擊「**載入 CSR 檔案**」選擇 `.csr` 或 `.pem` 檔案，或直接貼上 PEM 內容
2. 點擊「**解碼**」
3. 下方顯示 Subject 欄位、SAN、公鑰資訊、簽名演算法

### 3. 驗證憑證鏈

用於驗證憑證鏈是否正確（順序、簽章、有效期）。

1. 點擊「**載入憑證檔案**」選擇包含多張憑證的 PEM 檔案，或直接貼上 PEM 內容
2. 點擊「**驗證**」
3. 顯示每張憑證的 Subject、Issuer、有效期
4. 顯示驗證結果：通過或失敗（含錯誤原因）

### 4. 排序憑證鏈

用於將無序的憑證自動排列為正確順序（leaf → intermediate → root）。

1. 點擊「**載入憑證檔案**」或貼上包含多張憑證的 PEM 內容
2. 點擊「**分析並排序**」
3. 上方顯示排序結果，下方顯示排序後的 PEM 內容
4. 點擊「**儲存**」將排序後的憑證鏈匯出為 `.pem` 檔案

### 5. PFX 轉換

用於將 PFX/P12 格式憑證轉換為 PEM 格式的 CRT 與 KEY。

1. 點擊「**載入 PFX 檔案**」選擇 `.pfx` 或 `.p12` 檔案
2. 如有密碼，在密碼欄位中輸入（無密碼則留空）
3. 點擊「**轉換**」
4. 顯示憑證資訊（Subject、Issuer、有效期、序號）
5. 選擇儲存位置後產出：
   - `{名稱}.crt` — 主憑證
   - `{名稱}.key` — 私鑰
   - `{名稱}_chain.crt` — 附加憑證鏈（如有）

### 6. 自簽憑證

用於產生自簽憑證，適用於開發測試環境。

1. 填寫 **通用名稱 (CN)**（必填），例如 `localhost`
2. 視需要填寫其他 Subject 欄位
3. 選擇 **金鑰長度**（2048 或 4096）
4. 設定 **有效天數**（預設 365）
5. 如需產生 CA 憑證，勾選「**CA 憑證**」
6. 如需 SAN，在文字區域中每行輸入一筆：
   ```
   DNS:localhost
   IP:127.0.0.1
   ```
7. 點擊「**產生自簽憑證**」，選擇儲存位置
8. 產出檔案：`{CN}.crt`（憑證）與 `{CN}.key`（私鑰）

## 開發

```bash
# 安裝開發相依套件
uv sync --all-groups

# 執行測試
uv run pytest tests/ -v
```

## 授權

MIT License
