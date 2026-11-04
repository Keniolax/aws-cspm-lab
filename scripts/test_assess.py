"""Unit tests for assess.py, using synthetic Prowler 5.x CSV fixtures.

The fixture rows follow the Prowler 5.47.0 findings CSV: `;` delimiter and
the column set from prowler/lib/outputs/csv/csv.py, transform(). Only the
three columns assess.py reads are filled in.
"""
import csv
from pathlib import Path

import assess
from assess import ACCEPTED, TRACKED_CHECKS

HEADER = [
    "AUTH_METHOD", "TIMESTAMP", "ACCOUNT_UID", "ACCOUNT_NAME", "ACCOUNT_EMAIL",
    "ACCOUNT_ORGANIZATION_UID", "ACCOUNT_ORGANIZATION_NAME", "ACCOUNT_TAGS",
    "FINDING_UID", "PROVIDER", "CHECK_ID", "CHECK_TITLE", "CHECK_TYPE",
    "STATUS", "STATUS_EXTENDED", "MUTED", "SERVICE_NAME", "SUBSERVICE_NAME",
    "SEVERITY", "RESOURCE_TYPE", "RESOURCE_UID", "RESOURCE_NAME",
    "RESOURCE_DETAILS", "RESOURCE_TAGS", "PARTITION", "REGION",
    "DESCRIPTION", "RISK", "RELATED_URL", "REMEDIATION_RECOMMENDATION_TEXT",
    "REMEDIATION_RECOMMENDATION_URL", "REMEDIATION_CODE_NATIVEIAC",
    "REMEDIATION_CODE_TERRAFORM", "REMEDIATION_CODE_CLI",
    "REMEDIATION_CODE_OTHER", "COMPLIANCE", "CATEGORIES", "DEPENDS_ON",
    "RELATED_TO", "NOTES", "PROWLER_VERSION", "ADDITIONAL_URLS",
    "ACCOUNT_OU_UID", "ACCOUNT_OU_NAME",
]

LAB = "arn:aws:s3:::seceng-cspm-lab-000000000000"
AUDIT = "arn:aws:s3:::seceng-cspm-lab-audit-000000000000"
TRAIL = "arn:aws:cloudtrail:us-east-1:000000000000:trail/seceng-cspm-lab-trail"

# Untracked checks that pass on the lab bucket in both scans.
PASSING = ["s3_bucket_public_write_acl", "s3_bucket_default_encryption"]

Row = tuple[str, str, str]  # check_id, status, resource_uid


def write_scan(directory: Path, rows: list[Row]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "prowler.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(HEADER)
        for check_id, status, resource in rows:
            row = [""] * len(HEADER)
            row[HEADER.index("CHECK_ID")] = check_id
            row[HEADER.index("STATUS")] = status
            row[HEADER.index("RESOURCE_UID")] = resource
            writer.writerow(row)
    return directory


def vuln_rows() -> list[Row]:
    """The before scan: every "flip" check fails; "added" checks have no row,
    because the trail they report on does not exist yet."""
    rows = [(c, "FAIL", LAB) for c, kind in TRACKED_CHECKS.items() if kind == "flip"]
    return rows + [(c, "PASS", LAB) for c in PASSING]


def fixed_rows() -> list[Row]:
    """The after scan: every tracked check passes, and the accepted
    trail-only checks fail on the new trail."""
    rows = [(c, "PASS", LAB) for c in TRACKED_CHECKS]
    rows += [(c, "PASS", LAB) for c in PASSING]
    rows += [(c, "FAIL", TRAIL) for c in ACCEPTED]
    return rows


def run(tmp_path: Path, before: list[Row], after: list[Row]) -> int:
    b = write_scan(tmp_path / "before", before)
    a = write_scan(tmp_path / "after", after)
    return assess.main(["assess.py", str(b), str(a)])


def test_full_remediation_passes(tmp_path, capsys):
    assert run(tmp_path, vuln_rows(), fixed_rows()) == 0
    out = capsys.readouterr().out
    assert f"OK: {len(TRACKED_CHECKS)} tracked checks cleared" in out
    assert "cloudtrail_kms_encryption_enabled: no KMS" in out


def test_same_scan_for_both_fails(tmp_path, capsys):
    """The kill-bar: comparing the vulnerable scan to itself must fail."""
    assert run(tmp_path, vuln_rows(), vuln_rows()) == 1


def test_added_check_absent_before_is_not_a_miss(tmp_path, capsys):
    """A trail-only check has no row before the trail exists. That is
    expected, and must not read as an undetected misconfiguration."""
    assert not any(c == "cloudtrail_log_file_validation_enabled" for c, _, _ in vuln_rows())
    assert run(tmp_path, vuln_rows(), fixed_rows()) == 0


def test_added_check_already_passing_before_fails(tmp_path, capsys):
    """If a trail with validation already existed, the lab did not fix it."""
    before = vuln_rows() + [("cloudtrail_log_file_validation_enabled", "PASS", TRAIL)]
    assert run(tmp_path, before, fixed_rows()) == 1
    assert "already passing before" in capsys.readouterr().out


def test_tracked_check_failing_on_new_resource_fails(tmp_path, capsys):
    """The lab bucket is fixed but the new audit bucket is not: still a FAIL."""
    after = fixed_rows() + [("s3_bucket_secure_transport_policy", "FAIL", AUDIT)]
    assert run(tmp_path, vuln_rows(), after) == 1
    assert "s3_bucket_secure_transport_policy: still failing" in capsys.readouterr().out


def test_regression_is_caught(tmp_path, capsys):
    """A resource that passed a check before and fails it after fails the run."""
    after = [r for r in fixed_rows() if r[0] != "s3_bucket_public_write_acl"]
    after.append(("s3_bucket_public_write_acl", "FAIL", LAB))
    assert run(tmp_path, vuln_rows(), after) == 1
    assert "regressed on" in capsys.readouterr().out


def test_unaccepted_new_failure_is_caught(tmp_path, capsys):
    """A check with no FAIL before and a FAIL after fails the run unless the
    README accepts it."""
    after = fixed_rows() + [
        ("ec2_securitygroup_allow_ingress_from_internet_to_any_port", "FAIL", "sg-0lab")
    ]
    assert run(tmp_path, vuln_rows(), after) == 1
    assert "new failure" in capsys.readouterr().out


def test_undetected_misconfiguration_fails(tmp_path, capsys):
    """A "flip" check with no FAIL in the before scan fails the run."""
    before = [r for r in vuln_rows() if r[0] != "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"]
    assert run(tmp_path, before, fixed_rows()) == 1
    assert "not detected as FAIL" in capsys.readouterr().out


def test_check_vanishing_from_after_fails(tmp_path, capsys):
    """A tracked check absent from the after scan fails the run."""
    after = [r for r in fixed_rows() if r[0] != "iam_password_policy_symbol"]
    assert run(tmp_path, vuln_rows(), after) == 1
    assert "still failing (or absent)" in capsys.readouterr().out


def test_rejects_compliance_csv(tmp_path):
    """A per-framework compliance CSV (CHECKID, not CHECK_ID) is refused."""
    bad = tmp_path / "before"
    bad.mkdir()
    (bad / "prowler.csv").write_text(
        "PROVIDER;REQUIREMENTS_ID;STATUS;RESOURCEID;CHECKID\naws;1.1;FAIL;x;y\n",
        encoding="utf-8",
    )
    after = write_scan(tmp_path / "after", fixed_rows())
    try:
        assess.main(["assess.py", str(bad), str(after)])
    except SystemExit as e:
        assert "missing columns" in str(e)
    else:
        raise AssertionError("expected SystemExit for a compliance CSV")
