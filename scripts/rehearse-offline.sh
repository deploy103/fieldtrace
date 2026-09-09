#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname -- "${SCRIPT_DIR}")"
WHEELHOUSE_DIR="${1:-${PROJECT_DIR}/wheelhouse}"
FIELDTRACE_PYTHON_BIN="${FIELDTRACE_PYTHON_BIN:-python3.12}"
REHEARSAL_DIR="$(mktemp -d)"

cleanup() {
  rm -rf -- "${REHEARSAL_DIR}"
}
trap cleanup EXIT

if [[ ! -d "${WHEELHOUSE_DIR}" ]]; then
  echo "wheelhouse를 찾을 수 없습니다: ${WHEELHOUSE_DIR}" >&2
  exit 2
fi
WHEELHOUSE_DIR="$(CDPATH= cd -- "${WHEELHOUSE_DIR}" && pwd)"
if ! command -v unshare >/dev/null 2>&1; then
  echo "네트워크 격리를 검증할 unshare가 없습니다. 리허설 완료로 간주하지 않습니다." >&2
  exit 2
fi
if ! unshare --user --map-root-user --net true 2>/dev/null; then
  echo "네트워크 namespace를 만들 권한이 없습니다. 리허설 완료로 간주하지 않습니다." >&2
  exit 2
fi

"${FIELDTRACE_PYTHON_BIN}" -m venv "${REHEARSAL_DIR}/venv"
OFFLINE_PIP="${REHEARSAL_DIR}/venv/bin/pip"
OFFLINE_FIELDTRACE="${REHEARSAL_DIR}/venv/bin/fieldtrace"
CASE_DIR="${REHEARSAL_DIR}/case"
REPORT_PATH="${REHEARSAL_DIR}/fieldtrace-offline.html"

cd -- "${REHEARSAL_DIR}"
unshare --user --map-root-user --net -- env \
  PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
  "${OFFLINE_PIP}" install --no-index --find-links "${WHEELHOUSE_DIR}" fieldtrace-ctf
unshare --user --map-root-user --net -- "${OFFLINE_FIELDTRACE}" doctor
unshare --user --map-root-user --net -- "${OFFLINE_FIELDTRACE}" analyze \
  "${PROJECT_DIR}/samples/generic.txt" --profile full --case "${CASE_DIR}"
unshare --user --map-root-user --net -- "${OFFLINE_FIELDTRACE}" search \
  --case "${CASE_DIR}" --text 'FLAG{'
unshare --user --map-root-user --net -- "${OFFLINE_FIELDTRACE}" report \
  --case "${CASE_DIR}" --format html --output "${REPORT_PATH}"

test -s "${REPORT_PATH}"
echo "네트워크 격리 설치·분석·검색·HTML 보고서 리허설 통과"
