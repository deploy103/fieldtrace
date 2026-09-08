#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname -- "${SCRIPT_DIR}")"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv가 필요합니다. 공식 설치 안내에 따라 준비한 뒤 다시 실행하세요." >&2
  exit 2
fi

cd -- "${PROJECT_DIR}"
uv sync --frozen --all-groups
echo "준비 완료. ./run.sh doctor 로 확인하세요."

