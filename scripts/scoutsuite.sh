#!/usr/bin/env bash
# ScoutSuite as a second opinion beside Prowler, run once against each state.
# Its HTML report is generated output and is not committed (.gitignore drops
# evidence/scoutsuite/); the findings that matter go into docs/report.md.
# usage: scripts/scoutsuite.sh <vuln|fixed> <report-directory>
set -euo pipefail

mode="${1:?usage: scoutsuite.sh <vuln|fixed> <report-directory>}"
outdir="${2:?usage: scoutsuite.sh <vuln|fixed> <report-directory>}"

if ! command -v scout >/dev/null 2>&1; then
  echo "scout is not installed: pip install scoutsuite" >&2
  exit 1
fi

mkdir -p "$outdir"
# --no-browser: do not open a browser; this is a headless VM.
# --force: overwrite a previous run's report in the same directory.
scout aws \
  --no-browser \
  --force \
  --report-dir "$outdir" \
  --report-name "scoutsuite-${mode}"

echo "scoutsuite.sh: wrote the $mode report under $outdir"
