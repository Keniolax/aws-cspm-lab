"""Tests for scan.sh against a fake `prowler` that behaves like 5.47.0 in the
three ways that matter here:

  * it exits 3 when any check fails, unless --ignore-exit-code-3 is passed;
  * it writes one CSV per compliance framework into <dir>/compliance/ next to
    the findings CSV, whose name is <dir>/<--output-filename>.csv or, without
    that flag, a timestamped name;
  * it skips security groups attached to nothing unless
    --scan-unused-services is passed.
"""
import os
import stat
import subprocess
from pathlib import Path

SCAN = Path(__file__).parent / "scan.sh"
SG_CHECK = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"

FAKE_PROWLER = r'''#!/usr/bin/env python3
import sys
from pathlib import Path

args = sys.argv[1:]
def value(flag, default=None):
    return args[args.index(flag) + 1] if flag in args else default

out = Path(value("--output-directory", "output"))
name = value("--output-filename", "prowler-output-000000000000-20261104000000")
(out / "compliance").mkdir(parents=True, exist_ok=True)
# Compliance CSVs first, with their own header (CHECKID, not CHECK_ID).
for fw in ("aws_well_architected", "cis_2.0_aws", "nist_800_53"):
    (out / "compliance" / f"{name}_{fw}.csv").write_text(
        "PROVIDER;REQUIREMENTS_ID;STATUS;RESOURCEID;CHECKID\naws;1.1;FAIL;x;y\n")
rows = ["s3_bucket_public_access;FAIL;arn:aws:s3:::lab"]
if "--scan-unused-services" in args:
    rows.append("%s;FAIL;sg-0lab")
(out / f"{name}.csv").write_text(
    "CHECK_ID;STATUS;RESOURCE_UID\n" + "\n".join(rows) + "\n")
if "--ignore-exit-code-3" not in args and "-z" not in args:
    sys.exit(3)
''' % SG_CHECK


def run_scan(tmp_path: Path) -> subprocess.CompletedProcess:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    prowler = fake_bin / "prowler"
    prowler.write_text(FAKE_PROWLER)
    prowler.chmod(prowler.stat().st_mode | stat.S_IXUSR)
    env = dict(os.environ, PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    return subprocess.run(
        ["bash", str(SCAN), "vuln", str(tmp_path / "before")],
        env=env, capture_output=True, text=True,
    )


def test_scan_survives_failed_checks(tmp_path):
    """The before scan fails checks on purpose; the script must still finish."""
    result = run_scan(tmp_path)
    assert result.returncode == 0, result.stderr


def test_scan_copies_the_findings_csv_not_a_compliance_csv(tmp_path):
    run_scan(tmp_path)
    header = (tmp_path / "before" / "prowler.csv").read_text().splitlines()[0]
    assert header.split(";")[0] == "CHECK_ID"


def test_scan_reports_the_unattached_security_group(tmp_path):
    run_scan(tmp_path)
    assert SG_CHECK in (tmp_path / "before" / "prowler.csv").read_text()
