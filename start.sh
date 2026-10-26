#!/usr/bin/env bash
# One-command local stack.
# Backend: FastAPI/uvicorn on 127.0.0.1:8000
# Frontend: Vite dev server on 127.0.0.1:5173
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { printf "${BLUE}[analyzer]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[analyzer]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[analyzer]${NC} %s\n" "$*"; }
fail() { printf "${RED}[analyzer]${NC} %s\n" "$*" >&2; }

# --- Python -----------------------------------------------------------------
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    fail "Python 3.10+ is required but was not found on PATH."
    exit 1
  fi
fi

if [[ "$PYTHON_BIN" == */* || "$PYTHON_BIN" == *\\* ]]; then
  VENV_PY="$PYTHON_BIN"
elif [[ -x "$ROOT/.venv/Scripts/python.exe" ]]; then
  VENV_PY="$ROOT/.venv/Scripts/python.exe"
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  VENV_PY="$ROOT/.venv/bin/python"
else
  info "Creating Python virtual environment in .venv"
  "$PYTHON_BIN" -m venv "$ROOT/.venv"
  if [[ -x "$ROOT/.venv/Scripts/python.exe" ]]; then
    VENV_PY="$ROOT/.venv/Scripts/python.exe"
  else
    VENV_PY="$ROOT/.venv/bin/python"
  fi
fi

DEPS_MARKER="$ROOT/.venv/.analyzer-deps"
if [[ ! -f "$DEPS_MARKER" || "$ROOT/backend/requirements.txt" -nt "$DEPS_MARKER" ]]; then
  info "Installing backend dependencies"
  "$VENV_PY" -m pip install --upgrade pip --quiet
  "$VENV_PY" -m pip install -r "$ROOT/backend/requirements.txt" --quiet
  touch "$DEPS_MARKER"
fi

# --- Node -------------------------------------------------------------------
if ! command -v npm >/dev/null 2>&1; then
  fail "Node.js 18+ and npm are required but npm was not found on PATH."
  exit 1
fi

frontend_platform_pkg() {
  local kernel arch
  kernel="$(uname -s)"
  arch="$(uname -m)"
  case "$kernel" in
    MINGW*|MSYS*|CYGWIN*)
      case "$arch" in
        x86_64|amd64) echo "win32-x64" ;;
        aarch64|arm64) echo "win32-arm64" ;;
      esac
      ;;
    Linux)
      case "$arch" in
        x86_64|amd64) echo "linux-x64" ;;
        aarch64|arm64) echo "linux-arm64" ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64|amd64) echo "darwin-x64" ;;
        aarch64|arm64) echo "darwin-arm64" ;;
      esac
      ;;
  esac
}

# node_modules is not portable: a Windows install lacks @esbuild/linux-*, and a
# WSL install lacks @esbuild/win32-*.  npm can keep both variants side by side,
# so add the current platform's native packages without wiping the other set.
PLATFORM_ESBUILD="$(frontend_platform_pkg)"
NEED_NPM_INSTALL=0
if [[ ! -d "$ROOT/frontend/node_modules" ]]; then
  NEED_NPM_INSTALL=1
elif [[ -n "$PLATFORM_ESBUILD" && ! -d "$ROOT/frontend/node_modules/@esbuild/$PLATFORM_ESBUILD" ]]; then
  NEED_NPM_INSTALL=1
fi
if [[ "$NEED_NPM_INSTALL" == "1" ]]; then
  if [[ -d "$ROOT/frontend/node_modules" ]]; then
    info "Adding frontend native packages for this platform"
  else
    info "Installing frontend dependencies"
  fi
  (cd "$ROOT/frontend" && npm install --no-audit --no-fund)
fi

# --- Process management -----------------------------------------------------
BACK_PID=""; FRONT_PID=""
kill_tree() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  if [[ "${OS:-}" == "Windows_NT" ]] && command -v taskkill >/dev/null 2>&1; then
    taskkill //PID "$pid" //T //F >/dev/null 2>&1 || true
  else
    pkill -TERM -P "$pid" >/dev/null 2>&1 || true
    kill -TERM "$pid" >/dev/null 2>&1 || true
  fi
}
cleanup() {
  trap - EXIT INT TERM
  info "Shutting down analyzer services"
  kill_tree "$FRONT_PID"
  kill_tree "$BACK_PID"
  wait "$FRONT_PID" "$BACK_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

info "Starting FastAPI backend on http://127.0.0.1:8000"
(
  cd "$ROOT/backend"
  exec "$VENV_PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
) &
BACK_PID=$!

info "Starting Vite frontend on http://127.0.0.1:5173"
(
  cd "$ROOT/frontend"
  exec npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
) &
FRONT_PID=$!

if command -v curl >/dev/null 2>&1; then
  for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:8000/api/health" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
fi

printf "\n"
ok "API      http://127.0.0.1:8000/docs"
ok "Workbench http://127.0.0.1:5173"
printf "   ${YELLOW}Ctrl+C stops both services.${NC}\n\n"

set +e
wait -n "$BACK_PID" "$FRONT_PID"
STATUS=$?
set -e
if [[ $STATUS -ne 0 ]]; then
  warn "A service exited with status $STATUS; stopping the remaining service."
else
  warn "A service exited; stopping the remaining service."
fi
exit "$STATUS"
