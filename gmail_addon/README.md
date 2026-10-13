# Inbox Sentry Gmail Add-on

這個目錄提供 Google Apps Script Gmail Add-on 範本，讓使用者在 Gmail 右側欄對目前郵件送出人工標註。

## 部署方式

1. 到 <https://script.google.com/> 建立新專案。
2. 將 `Code.gs` 貼到 Apps Script 編輯器。
3. 將 `appsscript.json` 貼到 Manifest。
4. 在 Apps Script 的 Project Settings > Script properties 新增：

```text
FINALX_API_BASE_URL=https://你的公開 API 網址
FINALX_API_TOKEN=你在後端 .env 設定的 API_TOKEN
```

本機測試時可以先用 Cloudflare Tunnel 或 ngrok 將 FastAPI `http://127.0.0.1:8008` 暴露成 HTTPS，因為 Google Add-on 需要能從 Google 伺服器連到 API。

## 功能

- 在 Gmail 郵件右側欄顯示 Inbox Sentry 操作卡。
- 會把目前郵件的寄件者、主旨與純文字內容送到 `/api/analyze-text`，顯示即時風險分數、原因與摘要。
- 支援送出 `false_positive`、`confirmed_threat`、`false_negative`。
- 標註會寫入 `/api/feedback`，預設進入 Dashboard 待審核。
- Dashboard 批准後，資料會寫入 MongoDB `labeled_dataset`，並更新寄件者 reputation。

## 注意

若後端 `.env` 設定 `API_TOKEN`，Add-on 也必須設定相同的 `FINALX_API_TOKEN`，才能送出人工標註與讀取受保護的 Dashboard API。公開部署時仍建議搭配反向代理、Cloudflare Access 或 Google Pub/Sub OIDC 驗證。
