#!/usr/bin/env bash
#
# Automated SecScan run against nanocurrency/nano-node.
# Triage mode: architecture + threat model + secrets + OSV.dev CVEs.
# Skips per-file LLM — nano-node is hundreds of C++ files; a full pass on a
# local 27B would take many hours.
#
# Usage: ./scripts/scan-nano-node.sh [full]
#   full  -> run per-file LLM pass as well (hours, not minutes)

set -euo pipefail

REPO="nanocurrency/nano-node"
MODEL="qwen-32k"                  # 32768-ctx instance — large enough for architecture + synthesis passes
LENSES="security,reliability,correctness"   # relevant for a consensus node
SECSCAN_ROOT="/Users/jhammant/dev/SecScan"
LOG_DIR="${SECSCAN_ROOT}/.secscan/logs"
TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${LOG_DIR}/nano-node-${TS}.log"

MODE_FLAG="--no-files"
if [[ "${1:-}" == "full" ]]; then
  MODE_FLAG=""
  echo ">>> FULL mode: per-file LLM enabled. This will take hours."
else
  echo ">>> TRIAGE mode: --no-files. Arch + threat model + secrets + deps only."
fi

mkdir -p "${LOG_DIR}"

# Put lms on PATH for this run
export PATH="${HOME}/.lmstudio/bin:${PATH}"

# Activate the SecScan venv
# shellcheck disable=SC1091
source "${SECSCAN_ROOT}/.venv/bin/activate"

cd "${SECSCAN_ROOT}"

echo ">>> 1/3 Verifying environment (secscan doctor)"
secscan doctor

echo ">>> 2/3 Confirming model is loaded"
if ! lms ps | grep -q "qwen/qwen3.6-27b"; then
  echo "Model not loaded — loading qwen/qwen3.6-27b"
  lms load qwen/qwen3.6-27b
fi

echo ">>> 3/3 Running scan against ${REPO}"
echo ">>> Model:  ${MODEL}"
echo ">>> Lenses: ${LENSES}"
echo ">>> Log:    ${LOG_FILE}"
echo

secscan scan "${REPO}" \
  --model "${MODEL}" \
  --lens "${LENSES}" \
  ${MODE_FLAG} \
  2>&1 | tee "${LOG_FILE}"

echo
echo ">>> Done. Reports in: ${SECSCAN_ROOT}/.secscan/reports/"
ls -la "${SECSCAN_ROOT}/.secscan/reports/" | grep nano-node || true
