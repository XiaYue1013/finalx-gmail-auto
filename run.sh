#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"
PYTEST="$ROOT_DIR/.venv/bin/pytest"
UVICORN="$ROOT_DIR/.venv/bin/uvicorn"

if [ ! -x "$PYTHON" ]; then
  echo "找不到 $PYTHON，請先在 FINALX_GMAIL_AUTO 建立 .venv 並安裝 requirements.txt。"
  exit 1
fi

case "${1:-auto}" in
  auth)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli auth
    ;;
  dry-run)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli scan-once --dry-run
    ;;
  recheck)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli scan-once --dry-run --include-processed
    ;;
  scan)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli scan-once
    ;;
  demo-insert)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" batch_test_insert.py "$@"
    ;;
  demo-insert-1)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" batch_test_insert.py --wave 1 "$@"
    ;;
  demo-insert-2)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" batch_test_insert.py --wave 2 "$@"
    ;;
  demo-insert-3)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" batch_test_insert.py --wave 3 "$@"
    ;;
  record-demo)
    shift
    cd "$ROOT_DIR"
    exec "$ROOT_DIR/record_demo.sh" "$@"
    ;;
  demo-check)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" tools/demo_readiness.py "$@"
    ;;
  evaluate)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" tools/generate_evaluation_report.py "$@"
    ;;
  evaluate-setfit)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" tools/evaluate_setfit_challenge.py "$@"
    ;;
  train-setfit)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" tools/train_setfit_classifier.py "$@"
    ;;
  package)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" tools/build_submission_zip.py "$@"
    ;;
  watch)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli watch
    ;;
  watch-loop)
    cd "$ROOT_DIR"
    INTERVAL="${GMAIL_WATCH_RENEW_SECONDS:-86400}"
    while true; do
      "$PYTHON" -m app.cli watch || true
      sleep "$INTERVAL"
    done
    ;;
  stop-watch)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli stop-watch
    ;;
  worker)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli poll
    ;;
  poll)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli poll
    ;;
  auto)
    cd "$ROOT_DIR"
    exec "$UVICORN" app.main:app --host 0.0.0.0 --port 8008 --reload
    ;;
  status)
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli status
    ;;
  api)
    cd "$ROOT_DIR"
    exec "$UVICORN" app.main:app --host 0.0.0.0 --port 8008 --reload
    ;;
  test)
    cd "$ROOT_DIR"
    exec "$PYTEST"
    ;;
  analyze-text)
    shift
    cd "$ROOT_DIR"
    exec "$PYTHON" -m app.cli analyze-text "$@"
    ;;
  help|*)
    cat <<'USAGE'
FINALX_GMAIL_AUTO independent runner

Usage:
  ./run.sh               啟動 Gmail Push webhook API
  ./run.sh auto          啟動 Gmail Push webhook API
  ./run.sh auth          Gmail OAuth 授權
  ./run.sh watch         註冊 Gmail users.watch 到 Cloud Pub/Sub topic
  ./run.sh watch-loop    每 24 小時自動續約 Gmail watch
  ./run.sh stop-watch    停止 Gmail watch
  ./run.sh dry-run       掃描 Gmail 但不修改標籤
  ./run.sh recheck       重新分析已處理信件，不修改 Gmail 或 state
  ./run.sh scan          掃描一次並標記高風險信件
  ./run.sh demo-insert --wave 1 --interval 0
                          插入一波 10 封示範信，可用 --wave 1/2/3
  ./run.sh demo-insert-1  插入第一波 10 封示範信
  ./run.sh demo-insert-2  插入第二波 10 封示範信
  ./run.sh demo-insert-3  插入第三波 10 封示範信
  ./run.sh record-demo    啟動互動式錄影 Demo 流程
  ./run.sh demo-check     檢查簡報與現場 demo 是否準備完成
  ./run.sh evaluate       產生 EVALUATION_REPORT.md 與 data/evaluation_report.json
  ./run.sh evaluate-setfit 在未參與訓練的 challenge 信件上驗證 SetFit 泛化
  ./run.sh train-setfit   使用初始樣本與已批准人工回饋訓練 SetFit 模型
  ./run.sh package        建立乾淨 submission zip，排除 token/cache/data
  ./run.sh poll          輪詢 fallback：常駐掃描 Gmail
  ./run.sh worker        同 ./run.sh poll
  ./run.sh status        查看本機狀態與近期紀錄
  ./run.sh api           啟動 FastAPI at 127.0.0.1:8008
  ./run.sh test          執行測試
  ./run.sh analyze-text "文字"  手動分析文字
USAGE
    ;;
esac
