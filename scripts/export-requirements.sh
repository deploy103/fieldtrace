#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname -- "${SCRIPT_DIR}")"
OUTPUT_PATH="${1:-${PROJECT_DIR}/requirements.lock.txt}"

cd -- "${PROJECT_DIR}"
uv export --frozen --no-dev --no-emit-project --format requirements-txt \
  --output-file "${OUTPUT_PATH}"
echo "pip 호환 잠금 목록: ${OUTPUT_PATH}"

