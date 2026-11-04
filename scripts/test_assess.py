"""Unit tests for assess.py, using synthetic Prowler 5.x CSV fixtures.

The fixture rows follow the real Prowler CSV contract this lab depends on:
`;` delimiter and the transform() column set from prowler 5.47.0. Only the
two columns assess.py needs are populated.
"""
import csv
import sys
from pathlib import Path

# This is the shape of a real row (from prowler/lib/outputs/csv/csv.py,
# transform()); values are abbreviated.
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

PASSING_BEFORE = ["s3_bucket_public_write_acl", "iam_role_cross_service_confused_deputy"]


def write_scan(directory: Path, rows: list[tuple[str, str]]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "prowler.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(HEADER)
        for check_id, status in rows:
            row = [""] * len(HEADER)
            row[HEADER.index("CHECK_ID")] = check_id
            row[HEADER.index("STATUS")] = status
            writer.writerow(row)


def vuln_rows() -> list[tuple[str, str]]:
    """Every tracked check failing, plus two untracked passing checks."""
    from assess import TRACKED_CHECKS

    return [(c, "FAIL") for c in TRACKED_CHECKS] + [(c, "PASS") for c in PASSING_BEFORE]


def fixed_rows() -> list[tuple[str, str]]:
    """Every tracked check passing, untracked still passing."""
    from assess import TRACKED_CHECKS

    return [(c, "PASS") for c in TRACKED_CHECKS] + [(c, "PASS") for c in PASSING_BEFORE]


def run(before: Path, after: Path, capsys) -> int:
    import assess

    return assess.main(["assess.py", str(before), str(after)])


def test_all_flips_pass(tmp_path, capsys):
    before = tmp_path / "before"
    after = tmp_path / "after"
    write_scan(before, vuln_rows())
    write_scan(after, fixed_rows())
    assert run(before, after, capsys) == 0
    out = capsys.readouterr().out
    assert "18 tracked checks flipped" in out


def test_same_scan_for_both_fails(tmp_path, capsys):
    """The kill-bar: comparing the vulnerable scan to itself must fail."""
    before = tmp_path / "before"
    write_scan(before, vuln_rows())
    assert run(before, before, capsys) == 1


def test_regression_is_caught(tmp_path, capsys):
    """A check that passed before and fails after must fail the run."""
    before = tmp_path / "before"
    after = tmp_path / "after"
    write_scan(before, vuln_rows())
    rows = fixed_rows()
    rows = [r for r in rows if r[0] != "s3_bucket_public_write_acl"]
    rows.append(("s3_bucket_public_write_acl", "FAIL"))
    write_scan(after, rows)
    assert run(before, after, capsys) == 1
    out = capsys.readouterr().out
    assert "regressed" in out


def test_new_failure_after_is_caught(tmp_path, capsys):
    """A check that was absent before and fails after must fail the run."""
    before = tmp_path / "before"
    after = tmp_path / "after"
    write_scan(before, vuln_rows())
    rows = fixed_rows()
    rows.append(("ec2_securitygroup_allow_ingress_from_internet_to_any_port", "FAIL"))
    write_scan(after, rows)
    assert run(before, after, capsys) == 1
    out = capsys.readouterr().out
    assert "new failure" in out


def test_undetected_misconfiguration_fails(tmp_path, capsys):
    """A tracked check missing from the before scan fails the run."""
    before = tmp_path / "before"
    after = tmp_path / "after"
    rows = vuln_rows()
    rows = [r for r in rows if r[0] != "s3_bucket_public_access"]
    write_scan(before, rows)
    write_scan(after, fixed_rows())
    assert run(before, after, capsys) == 1
    out = capsys.readouterr().out
    assert "not detected as FAIL" in out


def test_check_vanishing_from_after_fails(tmp_path, capsys):
    """A tracked check absent from the after scan fails the run."""
    before = tmp_path / "before"
    after = tmp_path / "after"
    write_scan(before, vuln_rows())
    rows = [r for r in fixed_rows() if r[0] != "iam_password_policy_symbol"]
    write_scan(after, rows)
    assert run(before, after, capsys) == 1
    out = capsys.readouterr().out
    assert "still failing (or absent)" in out


def test_rejects_non_prowler_csv(tmp_path, capsys):
    """A CSV without the Prowler columns is refused, not mis-parsed."""
    bad = tmp_path / "before"
    bad.mkdir()
    (bad / "prowler.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    after = tmp_path / "after"
    write_scan(after, fixed_rows())
    try:
        run(bad, after, capsys)
    except SystemExit as e:
        assert "missing columns" in str(e)
    else:
        raise AssertionError("expected SystemExit for a non-Prowler CSV")