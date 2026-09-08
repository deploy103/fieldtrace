#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FIELDTRACE_BIN="${SCRIPT_DIR}/.venv/bin/fieldtrace"

if [[ ! -x "${FIELDTRACE_BIN}" ]]; then
  echo "FieldTrace 실행 환경이 없습니다: ${SCRIPT_DIR}/.venv" >&2
  echo "인터넷 가능한 준비 환경에서 'uv sync --all-groups'를 먼저 실행하세요." >&2
  exit 2
fi

cd -- "${SCRIPT_DIR}"
exec "${FIELDTRACE_BIN}" "$@"

