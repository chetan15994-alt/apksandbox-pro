#!/bin/zsh
set -u
clear
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1
BLUE='\033[1;34m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; RED='\033[1;31m'; RESET='\033[0m'
printf "${BLUE}APKSandbox Pro - Automatic Mac Launcher${RESET}\n\n"
fail(){ printf "\n${RED}ERROR: %s${RESET}\n" "$1"; printf "Press Return to close..."; read _; exit 1; }
command -v python3 >/dev/null 2>&1 || fail "Python 3 is not installed. Install Python 3 from python.org, then double-click this file again."
PYVER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
printf "Python %s detected.\n" "$PYVER"
if [ ! -d .venv ]; then
  printf "${YELLOW}First launch: creating private Python environment...${RESET}\n"
  python3 -m venv .venv || fail "Could not create the Python environment."
fi
source .venv/bin/activate || fail "Could not activate the Python environment."
STAMP=.venv/.requirements-installed
REQ_HASH="$(shasum -a 256 requirements.txt | awk '{print $1}')"
OLD_HASH="$(cat "$STAMP" 2>/dev/null || true)"
if [ "$REQ_HASH" != "$OLD_HASH" ]; then
  printf "${YELLOW}Installing required components. This is needed only on first launch...${RESET}\n"
  python -m pip install --upgrade pip || fail "Could not update pip. Check the internet connection."
  python -m pip install -r requirements.txt || fail "Dependency installation failed. Check the internet connection."
  printf "%s" "$REQ_HASH" > "$STAMP"
fi
PORT="$(python - <<'PY'
import socket
s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()
PY
)"
URL="http://127.0.0.1:$PORT"
printf "${YELLOW}Starting APKSandbox Pro on %s...${RESET}\n" "$URL"
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port "$PORT" > data/server.log 2>&1 &
SERVER_PID=$!
cleanup(){ printf "\nStopping APKSandbox Pro...\n"; kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
READY=0
for i in {1..80}; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then cat data/server.log; fail "The server stopped during startup. See data/server.log."
  fi
  if curl -fsS "$URL/api/health" >/dev/null 2>&1; then READY=1; break; fi
  sleep 0.25
done
[ "$READY" = 1 ] || fail "The application did not become ready. See data/server.log."
printf "${GREEN}APKSandbox Pro is ready.${RESET}\n"
printf "Opening the dashboard in the default browser...\n\n"
open "$URL"
printf "Keep this Terminal window open while using the app.\n"
printf "To stop APKSandbox Pro, return here and press Control+C.\n"
wait "$SERVER_PID"
