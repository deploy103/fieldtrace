#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname -- "${SCRIPT_DIR}")"
WHEELHOUSE_DIR="${1:-${PROJECT_DIR}/wheelhouse}"
REQUIREMENTS_PATH="${WHEELHOUSE_DIR}/requirements.lock.txt"
BUILD_DIR="$(mktemp -d)"

cleanup() {
  rm -rf -- "${BUILD_DIR}"
}
trap cleanup EXIT

if ! command -v uv >/dev/null 2>&1; then
  echo "uv가 필요합니다. 온라인 준비 환경에서 uv를 설치한 뒤 다시 실행하세요." >&2
  exit 2
fi

mkdir -p -- "${WHEELHOUSE_DIR}"
cd -- "${PROJECT_DIR}"
uv lock --check
uv export --frozen --no-dev --no-emit-project --format requirements-txt \
  --output-file "${REQUIREMENTS_PATH}"
uv build --wheel --out-dir "${BUILD_DIR}"
uv run python -m pip wheel --requirement "${REQUIREMENTS_PATH}" \
  --wheel-dir "${WHEELHOUSE_DIR}"
cp -- "${BUILD_DIR}"/fieldtrace_ctf-*.whl "${WHEELHOUSE_DIR}/"

echo "wheelhouse 준비 완료: ${WHEELHOUSE_DIR}"
echo "반입 전에 scripts/rehearse-offline.sh '${WHEELHOUSE_DIR}' 를 실행하세요."
