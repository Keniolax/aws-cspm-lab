#!/usr/bin/env python3
"""Compare the before and after Prowler CSVs and prove the remediation.

usage: python3 scripts/assess.py evidence/before evidence/after

Reads prowler.csv from each directory (Prowler 5.x CSV, `;` delimiter).
The account is the lab's throwaway account, so every resource in it belongs
to the lab and check IDs are matched over the whole account.

For every tracked check, requires:
  * at least one FAIL row in the before scan (the deliberate misconfiguration
    was actually detected), and
  * zero FAIL rows in the after scan (the scanner, not a write-up, says it is
    fixed).

Also refuses regressions: any check that passed in the before scan and fails
in the after scan is reported and fails the run, tracked or not.

Exits 0 only when every tracked check flipped FAIL -> PASS and nothing
regressed. Otherwise exits 1 with a per-check report.
"""
import csv
import sys
from pathlib import Path

# Prowler check IDs the lab's misconfigurations map to. Every one must flip
# from FAIL to PASS between the two scans.
TRACKED_CHECKS = [
    # S3 bucket and account public-access posture
    "s3_bucket_public_access",
    "s3_bucket_public_list_acl",
    "s3_bucket_level_public_access_block",
    "s3_account_level_public_access_blocks",
    "s3_bucket_acl_prohibited",
    "s3_bucket_object_versioning",
    "s3_bucket_secure_transport_policy",
    # EC2 security group
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    # IAM password policy
    "iam_password_policy_minimum_length_14",
    "iam_password_policy_lowercase",
    "iam_password_policy_uppercase",
    "iam_password_policy_number",
    "iam_password_policy_symbol",
    "iam_password_policy_reuse_24",
    "iam_password_policy_expires_passwords_within_90_days_or_less",
    # CloudTrail (absent in vuln, added by fixed)
    "cloudtrail_multi_region_enabled",
    "cloudtrail_multi_region_enabled_logging_management_events",
    "cloudtrail_log_file_validation_enabled",
]

REQUIRED_COLUMNS = ["CHECK_ID", "STATUS"]


def load_statuses(scan_dir: Path) -> dict[str, set[str]]:
    """Read <scan_dir>/prowler.csv and return {check_id: {statuses}}."""
    csv_path = scan_dir / "prowler.csv"
    if not csv_path.is_file():
        sys.exit(f"assess.py: {csv_path} not found")
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=";")
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            sys.exit(
                f"assess.py: {csv_path} is missing columns {missing}; "
                "is this a Prowler 5.x CSV?"
            )
        statuses: dict[str, set[str]] = {}
        for row in reader:
            check_id = (row["CHECK_ID"] or "").strip()
            status = (row["STATUS"] or "").strip().upper()
            if check_id and status:
                statuses.setdefault(check_id, set()).add(status)
        return statuses


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    before = load_statuses(Path(argv[1]))
    after = load_statuses(Path(argv[2]))

    failures = []
    print(f"{'check id':64} {'before':12} after")
    for check in TRACKED_CHECKS:
        b = before.get(check, set())
        a = after.get(check, set())
        detected = "FAIL" in b
        cleared = bool(a) and "FAIL" not in a and "PASS" in a
        print(f"{check:64} {','.join(sorted(b)) or '-':12} {','.join(sorted(a)) or '-'}")
        if not detected:
            failures.append(f"{check}: not detected as FAIL in the before scan")
        elif not cleared:
            failures.append(f"{check}: still failing (or absent) in the after scan")

    for check, a in after.items():
        if "FAIL" not in a:
            continue
        b = before.get(check, set())
        if not b:
            failures.append(f"{check}: new failure — not present before, fails after")
        elif "PASS" in b and "FAIL" not in b:
            failures.append(f"{check}: regressed — passed before, fails after")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  {f}")
        return 1
    print(f"\nOK: {len(TRACKED_CHECKS)} tracked checks flipped FAIL -> PASS, no regressions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))