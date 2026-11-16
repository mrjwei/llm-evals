#!/bin/bash
# Start Triage (Plan P6.8): double-click this file in Finder to open the cjp
# web app. It installs the Python packages uv.lock names, builds the
# interface when it is missing or older than its sources, then runs
# `cjp ui`, which opens the browser at http://127.0.0.1:8738/ (this Mac
# only). If cjp is already running there, it just opens the browser.
# Close this window, or press Ctrl-C in it, to stop the app.
set -u
cd "$(dirname "$0")" || exit 1
# Finder starts this without the shell's own setup, so also look where uv
# and Homebrew's Node usually live, after anything already on PATH.
export PATH="$PATH:$HOME/.local/bin:$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin"

say() { echo "[Start Triage] $*"; }
stop() {
  echo
  say "$1"
  [ -t 0 ] && read -r -p "Press Return to close this window. " _
  exit 1
}

command -v uv >/dev/null 2>&1 ||
  stop "uv is not installed. Install it from https://docs.astral.sh/uv/ (one command), then double-click this file again."

say "checking the Python packages"
uv sync --frozen --quiet ||
  stop "Installing the Python packages failed (see above). Check the internet connection, then double-click this file again."

# The interface (web/ui/dist/) is built from web/ui/src/ and the lock file.
needs_build() {
  [ -f web/ui/dist/index.html ] || return 0
  [ -n "$(find web/ui/src web/ui/index.html web/ui/package.json web/ui/package-lock.json web/ui/vite.config.ts \
          -newer web/ui/dist/index.html -print -quit 2>/dev/null)" ]
}

if needs_build; then
  if command -v npm >/dev/null 2>&1; then
    say "building the interface (needed once after each update; about a minute the first time)"
    (
      cd web/ui || exit 1
      if [ ! -f node_modules/.package-lock.json ] || [ package-lock.json -nt node_modules/.package-lock.json ]; then
        npm ci --no-audit --no-fund --loglevel=error || exit 1
      fi
      npm run build --silent
    ) || stop "Building the interface failed (see above). Node.js 22.12 or newer is needed: node --version"
  else
    say "Node.js is not installed, so the interface can't be built yet; the page that opens says what to do."
  fi
fi

say "starting cjp; the browser opens by itself. Keep this window open while you work."
exec uv run --frozen cjp ui "$@"
