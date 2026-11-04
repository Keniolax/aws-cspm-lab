#!/usr/bin/env bash
# Run Prowler against the lab account and copy its findings CSV to
# <outdir>/prowler.csv, the one file assess.py reads.
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

# --ignore-exit-code-3: Prowler exits 3 when any check fails. The before scan
#   fails on purpose, so without this flag `set -e` stops the script here and
#   the CSV is never copied. Other exit codes (real errors) still stop it.
# --scan-unused-services: Prowler skips security groups that are attached to
#   nothing. The lab's open-SSH group is attached to nothing, so without this
#   flag the misconfiguration is never reported.
# --output-filename: a fixed name, so the findings CSV is found by name and
#   never confused with the per-framework CSVs Prowler writes to raw/compliance/.
prowler aws \
  --region "$region" \
  --output-formats csv \
  --output-directory "$outdir/raw" \
  --output-filename prowler \
  --scan-unused-services \
  --ignore-exit-code-3 \
  --no-banner

csv="$outdir/raw/prowler.csv"
if [ ! -s "$csv" ]; then
  echo "scan.sh: $csv is missing or empty" >&2
  exit 1
fi
# Redact AWS access key IDs (AKIA.../ASIA...) from the committed CSV. They are
# public identifiers, not secret keys (Prowler never emits a secret key), but
# they identify a live key and this repo goes public, so only the raw copy
# under raw/ (git-ignored) keeps them. The redaction is deterministic, so the
# before and after CSVs stay comparable for assess.py.
sed -E 's/(AKIA|ASIA)[0-9A-Z]{16}/<redacted-access-key-id>/g' "$csv" > "$outdir/prowler.csv"
echo "scan.sh: wrote $outdir/prowler.csv ($mode scan)"
