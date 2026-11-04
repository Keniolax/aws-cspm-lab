#!/usr/bin/env bash
# Run Prowler against the lab account and normalize its CSV output to
# <outdir>/prowler.csv, so assess.py always reads the same file name.
# usage: scripts/scan.sh <vuln|fixed> <output-directory>
set -euo pipefail

mode="${1:?usage: scan.sh <vuln|fixed> <output-directory>}"
outdir="${2:?usage: scan.sh <vuln|fixed> <output-directory>}"
region="${AWS_REGION:-us-east-1}"

# Prowler 5.47.0 is the version this lab was built against. A newer one is
# fine to try, but the CSV layout is the contract assess.py depends on.
if ! command -v prowler >/dev/null 2>&1; then
  echo "prowler is not installed: pipx install prowler==5.47.0" >&2
  exit 1
fi

mkdir -p "$outdir/raw"
prowler aws --region "$region" --output-modes csv --output-directory "$outdir/raw"

csv=$(find "$outdir/raw" -name '*.csv' -type f | head -1)
if [ -z "$csv" ]; then
  echo "scan.sh: no prowler csv found under $outdir/raw" >&2
  exit 1
fi
cp "$csv" "$outdir/prowler.csv"
echo "scan.sh: wrote $outdir/prowler.csv ($mode scan)"