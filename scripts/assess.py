#!/usr/bin/env python3
"""Compare the before and after Prowler CSVs and prove the remediation.

usage: python3 scripts/assess.py evidence/before evidence/after

Reads prowler.csv from each directory (Prowler 5.x CSV, `;` delimiter). The
account is the lab's throwaway account, so check IDs are matched over the
whole account and findings are matched by check ID and resource.

Each tracked check has a kind:
  * "flip": the misconfigured resource exists in both scans. The before scan
    must report FAIL; the after scan must report PASS and no FAIL.
  * "added": the fixed module creates the resource (the CloudTrail trail), so
    Prowler has nothing to report on before. The before scan must not already
    PASS; the after scan must report PASS and no FAIL.

Outside the tracked checks, the run also fails on:
  * a regression: a resource that passed a check before and fails it after;
  * a new failure: a check with no FAIL before and a FAIL after, unless the
    check is in ACCEPTED (the README's limitations, accepted on cost).

Exits 0 only when every tracked check is cleared and nothing else got worse.
Otherwise exits 1 and names each problem.
"""
import csv
import sys
from pathlib import Path

# Prowler check IDs the lab's misconfigurations map to.
TRACKED_CHECKS = {
    # S3 bucket and account public-access posture
    "s3_bucket_public_access": "flip",
    "s3_bucket_public_list_acl": "flip",
    "s3_bucket_level_public_access_block": "flip",
    "s3_account_level_public_access_blocks": "flip",
    "s3_bucket_acl_prohibited": "flip",
    "s3_bucket_object_versioning": "flip",
    "s3_bucket_secure_transport_policy": "flip",
    # EC2 security group (reported only with --scan-unused-services)
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": "flip",
    # IAM password policy
    "iam_password_policy_minimum_length_14": "flip",
    "iam_password_policy_lowercase": "flip",
    "iam_password_policy_uppercase": "flip",
    "iam_password_policy_number": "flip",
    "iam_password_policy_symbol": "flip",
    "iam_password_policy_reuse_24": "flip",
    "iam_password_policy_expires_passwords_within_90_days_or_less": "flip",
    # CloudTrail. With no trail, these two report one FAIL per region...
    "cloudtrail_multi_region_enabled": "flip",
    "cloudtrail_multi_region_enabled_logging_management_events": "flip",
    # ...but this one reports only on trails that exist, so it is "added".
    "cloudtrail_log_file_validation_enabled": "added",
}

# Checks that report only on a trail that exists, so they first appear in the
# after scan, and that fail there because of a limitation the README accepts.
ACCEPTED = {
    "cloudtrail_kms_encryption_enabled": "no KMS customer-managed key",
    "cloudtrail_cloudwatch_logging_enabled": "trail ships to S3 only, no CloudWatch Logs",
    "cloudtrail_insights_exist": "no CloudTrail Insights",
    "cloudtrail_bucket_requires_mfa_delete": "MFA delete needs the root user",
    "cloudtrail_logs_s3_bucket_access_logging_enabled": "no S3 access logging",
}

REQUIRED_COLUMNS = ["CHECK_ID", "STATUS", "RESOURCE_UID"]

Scan = dict[str, dict[str, set[str]]]  # check_id -> resource_uid -> statuses


def load_scan(scan_dir: Path) -> Scan:
    """Read <scan_dir>/prowler.csv into {check_id: {resource_uid: {statuses}}}."""
    csv_path = scan_dir / "prowler.csv"
    if not csv_path.is_file():
        sys.exit(f"assess.py: {csv_path} not found")
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=";")
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            sys.exit(
                f"assess.py: {csv_path} is missing columns {missing}; "
                "is this a Prowler 5.x findings CSV?"
            )
        scan: Scan = {}
        for row in reader:
            check_id = (row["CHECK_ID"] or "").strip()
            status = (row["STATUS"] or "").strip().upper()
            resource = (row["RESOURCE_UID"] or "").strip()
            if check_id and status:
                scan.setdefault(check_id, {}).setdefault(resource, set()).add(status)
        return scan


def statuses(scan: Scan, check: str) -> set[str]:
    """Every status a check reported, over all resources."""
    found: set[str] = set()
    for per_resource in scan.get(check, {}).values():
        found |= per_resource
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    before = load_scan(Path(argv[1]))
    after = load_scan(Path(argv[2]))

    failures = []
    print(f"{'check id':64} {'kind':6} {'before':12} after")
    for check, kind in TRACKED_CHECKS.items():
        b = statuses(before, check)
        a = statuses(after, check)
        print(f"{check:64} {kind:6} {','.join(sorted(b)) or '-':12} {','.join(sorted(a)) or '-'}")
        if kind == "flip" and "FAIL" not in b:
            failures.append(f"{check}: not detected as FAIL in the before scan")
        elif kind == "added" and "PASS" in b:
            failures.append(f"{check}: already passing before, so the fix proves nothing")
        elif "FAIL" in a or "PASS" not in a:
            failures.append(f"{check}: still failing (or absent) in the after scan")

    accepted = []
    for check, resources in after.items():
        if check in TRACKED_CHECKS:
            continue
        a = statuses(after, check)
        if "FAIL" not in a:
            continue
        for resource, a_res in resources.items():
            b_res = before.get(check, {}).get(resource, set())
            if "FAIL" in a_res and "PASS" in b_res and "FAIL" not in b_res:
                failures.append(f"{check}: regressed on {resource} (passed before, fails after)")
        if "FAIL" not in statuses(before, check):
            if check in ACCEPTED:
                accepted.append(f"{check}: {ACCEPTED[check]}")
            else:
                failures.append(f"{check}: new failure (no FAIL before, fails after)")

    if accepted:
        print("\nAccepted new failures (README limitations):")
        for line in accepted:
            print(f"  {line}")
    if failures:
        print("\nFAILED:")
        for line in failures:
            print(f"  {line}")
        return 1
    print(f"\nOK: {len(TRACKED_CHECKS)} tracked checks cleared, nothing regressed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
