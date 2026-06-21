#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"
UVICORN="$ROOT_DIR/.venv/bin/uvicorn"
LOCAL_URL="${FINALX_LOCAL_URL:-http://127.0.0.1:8008}"
PUBLIC_URL="${FINALX_PUBLIC_URL:-https://public.example.test}"
API_LOG="$ROOT_DIR/data/demo-api.log"
API_TOKEN_VALUE=""

WAVE=1
LIMIT=5
INTERVAL=1
WAIT_SECONDS=90
AUTO_MODE=false
OPEN_BROWSER=true
SEND_EMAILS=true
RENEW_WATCH=true
FALLBACK_SCAN=true
API_PID=""
STARTED_API=false

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
  BLUE="$(tput setaf 4)"
  GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"
  RED="$(tput setaf 1)"
else
  BOLD=""
  RESET=""
  BLUE=""
  GREEN=""
  YELLOW=""
  RED=""
fi

usage() {
  cat <<'EOF'
FINALX Gmail Auto 錄影 Demo

Usage:
  ./record_demo.sh [options]

Options:
  --wave 1|2|3       測試信波次，預設 1
  --limit N          寄送前 N 封，預設 5；完整展示可設 10
  --interval N       每封寄送間隔秒數，預設 1
  --wait N           等待 Gmail Push 處理秒數，預設 90
  --fast             不等待按 Enter，適合先排練
  --dry-run          只展示測試信，不寫入 Gmail
  --no-browser       不自動開啟 Dashboard 與 Gmail
  --skip-watch       不重新註冊 Gmail Watch
  --no-fallback      Push 超時時不執行單次掃描
  -h, --help         顯示說明

Examples:
  ./record_demo.sh
  ./record_demo.sh --limit 10 --interval 2
  ./record_demo.sh --fast --dry-run
EOF
}

while (($#)); do
  case "$1" in
    --wave)
      WAVE="${2:-}"
      shift 2
      ;;
    --limit)
      LIMIT="${2:-}"
      shift 2
      ;;
    --interval)
      INTERVAL="${2:-}"
      shift 2
      ;;
    --wait)
      WAIT_SECONDS="${2:-}"
      shift 2
      ;;
    --fast)
      AUTO_MODE=true
      shift
      ;;
    --dry-run)
      SEND_EMAILS=false
      shift
      ;;
    --no-browser)
      OPEN_BROWSER=false
      shift
      ;;
    --skip-watch)
      RENEW_WATCH=false
      shift
      ;;
    --no-fallback)
      FALLBACK_SCAN=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "未知參數：$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$WAVE" =~ ^[123]$ ]]; then
  echo "--wave 必須是 1、2 或 3。" >&2
  exit 2
fi
if [[ ! "$LIMIT" =~ ^[1-9][0-9]*$ ]] || ((LIMIT > 10)); then
  echo "--limit 必須是 1 到 10。" >&2
  exit 2
fi
if [[ ! "$INTERVAL" =~ ^[0-9]+$ ]] || [[ ! "$WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--interval 必須是非負整數，--wait 必須是正整數。" >&2
  exit 2
fi

section() {
  printf '\n%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BLUE" "$BOLD" "$RESET"
  printf '%s%s%s%s\n' "$BOLD" "$BLUE" "$1" "$RESET"
  printf '%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n' "$BLUE" "$BOLD" "$RESET"
}

ok() {
  printf '%s✓%s %s\n' "$GREEN" "$RESET" "$1"
}

warn() {
  printf '%s!%s %s\n' "$YELLOW" "$RESET" "$1"
}

fail() {
  printf '%s✗%s %s\n' "$RED" "$RESET" "$1" >&2
}

pause_demo() {
  local message="${1:-按 Enter 繼續}"
  if [[ "$AUTO_MODE" == true ]] || [[ ! -t 0 ]]; then
    return
  fi
  printf '\n%s%s%s' "$BOLD" "$message" "$RESET"
  read -r _
}

cleanup() {
  if [[ "$STARTED_API" == true ]] && [[ -n "$API_PID" ]] && kill -0 "$API_PID" 2>/dev/null; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

http_ready() {
  curl --silent --show-error --fail --max-time 3 "$1/" >/dev/null 2>&1
}

dashboard_api_ready() {
  local args=(
    --silent
    --show-error
    --fail
    --max-time
    5
  )
  if [[ -n "$API_TOKEN_VALUE" ]]; then
    args+=(-H "X-FINALX-API-TOKEN: $API_TOKEN_VALUE")
  fi
  curl "${args[@]}" "$1/api/dashboard/metrics" >/dev/null 2>&1
}

start_api() {
  if http_ready "$LOCAL_URL"; then
    if dashboard_api_ready "$LOCAL_URL"; then
      ok "本機 API 與 Dashboard API 已在 $LOCAL_URL 正常運行，沿用現有程序。"
      return
    fi
    fail "$LOCAL_URL 已有程序，但 Dashboard API 不健康。"
    printf '請先停止舊的 uvicorn 程序，再重新執行本腳本。\n' >&2
    exit 1
  fi

  mkdir -p "$ROOT_DIR/data"
  : >"$API_LOG"
  (
    cd "$ROOT_DIR"
    exec "$UVICORN" app.main:app --host 127.0.0.1 --port 8008
  ) >>"$API_LOG" 2>&1 &
  API_PID=$!
  STARTED_API=true

  for _ in {1..30}; do
    if http_ready "$LOCAL_URL" && dashboard_api_ready "$LOCAL_URL"; then
      ok "本機 API 已啟動：$LOCAL_URL"
      return
    fi
    if ! kill -0 "$API_PID" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  fail "API 啟動失敗。最後 20 行 log："
  tail -n 20 "$API_LOG" >&2 || true
  exit 1
}

snapshot() {
  (
    cd "$ROOT_DIR"
    "$PYTHON" - <<'PY'
import json

from app.store import MongoStateStore

store = MongoStateStore()
metrics = store.dashboard_metrics()
actions = metrics["events"]["actions"]
state = metrics["state"]
print(json.dumps({
    "processed": state["processed_message_ids"],
    "events": metrics["events"]["total"],
    "marked": actions.get("marked", 0),
    "warned": actions.get("warned", 0),
    "errors": metrics["events"]["errors"],
    "last_push_at": state.get("last_push_at"),
}, ensure_ascii=False))
PY
  )
}

show_recent_results() {
  (
    cd "$ROOT_DIR"
    "$PYTHON" - "$LIMIT" <<'PY'
import sys

from app.store import MongoStateStore

limit = max(int(sys.argv[1]), 5)
items = MongoStateStore().list_events(limit=limit)

print(f"{'風險':<10} {'分數':>4}  {'動作':<8} {'原因':<12} 主旨")
print("-" * 76)
for item in items:
    subject = " ".join(str(item.get("subject") or "(無主旨)").split())
    if len(subject) > 34:
        subject = subject[:33] + "…"
    print(
        f"{str(item.get('risk_level') or '-').upper():<10} "
        f"{int(item.get('risk_score') or 0):>4}  "
        f"{str(item.get('action') or '-'):<8} "
        f"{str(item.get('label_reason') or '-'):<12} "
        f"{subject}"
    )
PY
  )
}

open_page() {
  local url="$1"
  if [[ "$OPEN_BROWSER" != true ]]; then
    return
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
  else
    warn "找不到 xdg-open，請手動開啟：$url"
  fi
}

section "FINALX Gmail Auto｜錄影 Demo"
printf '流程：Gmail 新信 → Cloud Pub/Sub → Webhook → 風險分析 → 自動標籤 → Dashboard\n'
printf '測試波次：%s｜信件數：%s｜寄送間隔：%s 秒\n' "$WAVE" "$LIMIT" "$INTERVAL"
printf 'Dashboard：%s/dashboard\n' "$LOCAL_URL"
printf '公開 Webhook：%s/api/gmail/push\n' "$PUBLIC_URL"
pause_demo "確認錄影已開始後，按 Enter 執行環境檢查..."

section "1/6 環境與依賴檢查"
for required in "$PYTHON" "$UVICORN" "$ROOT_DIR/.env" "$ROOT_DIR/token.json"; do
  if [[ ! -e "$required" ]]; then
    fail "缺少：$required"
    exit 1
  fi
done
command -v curl >/dev/null 2>&1 || {
  fail "缺少 curl。"
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  fail "缺少 jq。"
  exit 1
}
API_TOKEN_VALUE="$(
  cd "$ROOT_DIR"
  "$PYTHON" - <<'PY'
from app.config import Settings
print(Settings().api_token or "")
PY
)"

CHECK_STATUS=0
CHECK_OUTPUT="$(
  cd "$ROOT_DIR"
  "$PYTHON" - <<'PY'
from pathlib import Path

from app.config import Settings
from app.store import MongoStateStore

s = Settings()
checks = {
    "MongoDB 可連線": False,
    "Gmail Pub/Sub topic 已設定": bool(s.gmail_watch_topic_name),
    "SetFit 模型已就緒": (s.setfit_model_dir / "config.json").exists(),
    "Gmail OAuth client 存在": Path("credentials.json").exists() or bool(list(Path(".").glob("client_secret_*.json"))),
    "Gmail OAuth token 存在": s.token_file.exists(),
}
try:
    MongoStateStore().load_state()
    checks["MongoDB 可連線"] = True
except Exception:
    pass

for name, passed in checks.items():
    print(("OK" if passed else "FAIL") + "\t" + name)
if not all(checks.values()):
    raise SystemExit(1)
PY
)" || CHECK_STATUS=$?

while IFS=$'\t' read -r state label; do
  if [[ "$state" == "OK" ]]; then
    ok "$label"
  else
    printf '%s✗%s %s\n' "$RED" "$RESET" "$label"
  fi
done <<<"$CHECK_OUTPUT"

if ((CHECK_STATUS != 0)); then
  fail "環境檢查未通過，請先修正以上項目。"
  exit 1
fi

start_api
if http_ready "$PUBLIC_URL"; then
  ok "公開入口可連線，Pub/Sub 可呼叫部署端。"
else
  warn "公開入口目前無法連線；Push 可能需要稍後使用 fallback。"
fi
pause_demo "環境正常。按 Enter 展示單筆風險分析..."

section "2/6 單筆可疑內容分析"
ANALYZE_PAYLOAD='{"text":"Google Security final notice: your account will be suspended within 24 hours. Verify your password and SMS code now at http://g00gle-security.top/login/verify"}'
curl --silent --show-error --fail --max-time 45 \
  -H "Content-Type: application/json" \
  -d "$ANALYZE_PAYLOAD" \
  "$LOCAL_URL/api/analyze-text" |
  jq '{
    high_risk,
    risk_level,
    risk_score,
    confidence_score,
    label_reason,
    top_reasons: (.reasons[0:3]),
    evidence_sources: ([.evidence[].source] | unique)
  }'
pause_demo "已展示模型、規則與證據整合結果。按 Enter 準備 Gmail Push..."

section "3/6 Gmail Watch 與 Push 準備"
if [[ "$RENEW_WATCH" == true ]]; then
  if (
    cd "$ROOT_DIR"
    "$ROOT_DIR/run.sh" watch
  ); then
    ok "Gmail Watch 已註冊／續約。"
  else
    fail "Gmail Watch 註冊失敗，無法展示 Push 自動化。"
    exit 1
  fi
else
  warn "已略過 Watch 續約，使用目前既有設定。"
fi

BEFORE_JSON="$(snapshot)"
printf '目前狀態：已處理 %s 封｜高風險標記 %s｜中風險警告 %s｜錯誤 %s\n' \
  "$(jq -r '.processed' <<<"$BEFORE_JSON")" \
  "$(jq -r '.marked' <<<"$BEFORE_JSON")" \
  "$(jq -r '.warned' <<<"$BEFORE_JSON")" \
  "$(jq -r '.errors' <<<"$BEFORE_JSON")"

open_page "$LOCAL_URL/dashboard"
open_page "https://mail.google.com/mail/u/0/#inbox"
printf '\n錄影畫面建議：左側 Gmail，右側 Dashboard；終端機保留在下方。\n'
printf 'Gmail 可搜尋：label:"FINALX 高風險" 或 label:"FINALX 中風險"\n'
pause_demo "瀏覽器畫面排好後，按 Enter 插入示範信..."

section "4/6 插入混合風險示範信"
if [[ "$SEND_EMAILS" == true ]]; then
  (
    cd "$ROOT_DIR"
    "$ROOT_DIR/run.sh" demo-insert --wave "$WAVE" --limit "$LIMIT" --interval "$INTERVAL"
  )
else
  warn "Dry-run：不會寫入 Gmail。"
  (
    cd "$ROOT_DIR"
    "$ROOT_DIR/run.sh" demo-insert --wave "$WAVE" --limit "$LIMIT" --interval 0 --dry-run
  )
fi

if [[ "$SEND_EMAILS" != true ]]; then
  section "Dry-run 完成"
  printf '正式錄影時移除 --dry-run，即可展示 Gmail Push 與自動標籤。\n'
  exit 0
fi

section "5/6 等待 Pub/Sub Push 自動處理"
BEFORE_PROCESSED="$(jq -r '.processed' <<<"$BEFORE_JSON")"
TARGET_PROCESSED=$((BEFORE_PROCESSED + LIMIT))
DEADLINE=$((SECONDS + WAIT_SECONDS))
PUSH_COMPLETED=false

while ((SECONDS < DEADLINE)); do
  CURRENT_JSON="$(snapshot)"
  CURRENT_PROCESSED="$(jq -r '.processed' <<<"$CURRENT_JSON")"
  PROGRESS=$((CURRENT_PROCESSED - BEFORE_PROCESSED))
  if ((PROGRESS < 0)); then
    PROGRESS=0
  fi
  printf '\rPush 處理進度：%s/%s｜高風險 %s｜中風險 %s｜錯誤 %s   ' \
    "$PROGRESS" "$LIMIT" \
    "$(jq -r '.marked' <<<"$CURRENT_JSON")" \
    "$(jq -r '.warned' <<<"$CURRENT_JSON")" \
    "$(jq -r '.errors' <<<"$CURRENT_JSON")"
  if ((CURRENT_PROCESSED >= TARGET_PROCESSED)); then
    PUSH_COMPLETED=true
    break
  fi
  sleep 3
done
printf '\n'

if [[ "$PUSH_COMPLETED" == true ]]; then
  ok "Gmail Push 已自動處理本次示範信。"
elif [[ "$FALLBACK_SCAN" == true ]]; then
  warn "等待 ${WAIT_SECONDS} 秒後仍未全部收到 Push；現在執行單次掃描 fallback。"
  (
    cd "$ROOT_DIR"
    "$ROOT_DIR/run.sh" scan >/dev/null
  )
  ok "Fallback 掃描完成。錄影旁白應明確說明此步不是 Push。"
else
  warn "Push 等待逾時，依 --no-fallback 設定停止自動處理。"
fi

section "6/6 Demo 結果摘要"
AFTER_JSON="$(snapshot)"
printf '處理數變化：%s → %s\n' \
  "$(jq -r '.processed' <<<"$BEFORE_JSON")" \
  "$(jq -r '.processed' <<<"$AFTER_JSON")"
printf '高風險標記：%s → %s\n' \
  "$(jq -r '.marked' <<<"$BEFORE_JSON")" \
  "$(jq -r '.marked' <<<"$AFTER_JSON")"
printf '中風險警告：%s → %s\n\n' \
  "$(jq -r '.warned' <<<"$BEFORE_JSON")" \
  "$(jq -r '.warned' <<<"$AFTER_JSON")"
show_recent_results

printf '\n%s錄影收尾建議：%s\n' "$BOLD" "$RESET"
printf '1. 切到 Gmail，展示「FINALX 高風險／中風險」及理由標籤。\n'
printf '2. 切到 Dashboard 重新整理，打開一筆事件詳情。\n'
printf '3. 說明低風險信不標記，高風險信才自動處置。\n'
printf '4. 展示分數拆解、命中規則、URL／寄件驗證證據與建議。\n'

if [[ "$STARTED_API" == true ]]; then
  pause_demo "完成瀏覽器畫面錄製後按 Enter，腳本會停止本次啟動的 API..."
else
  pause_demo "完成瀏覽器畫面錄製後按 Enter 結束..."
fi
