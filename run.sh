#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi

if [ -r "/etc/security-news.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "/etc/security-news.env"
  set +a
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"

cd "$ROOT"
exec "$PYTHON_BIN" "$ROOT/security_news.py" "$@"
