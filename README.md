# aws-cspm-lab

A deliberately misconfigured AWS environment, the scanners that catch it, and
the remediation that clears it — proven with a before/after Prowler report
mapped to the CIS AWS Foundations Benchmark.

> **Warning — deliberately vulnerable.** `modules/vuln` opens an S3 bucket to
> the world, points SSH at the whole internet, and switches off the account's
> public-access guardrails on purpose, so Prowler and ScoutSuite have real
> findings to find. Run it only in a throwaway AWS account you control, and
> destroy it the same day (`make destroy`). It must never be deployed to a
> real account.

## What problem this solves

Most cloud breaches start as a configuration mistake, not an exploit: a bucket
left world-readable, a security group with SSH open to 0.0.0.0/0, a trail that
was never turned on. A CSPM (cloud security posture management) scanner reads
the account's configuration through the AWS API and flags those mistakes before
an attacker finds them. This lab makes the mistakes on purpose, catches them
with two open-source scanners, fixes them in Terraform, and proves the fix with
a re-scan.

## What you built

- **`modules/vuln`** — six deliberate misconfigurations across S3, EC2 and
  IAM: a public-read bucket with no public access block, no encryption, no
  HTTPS-only policy and versioning off; an account-level public access block
  switched off; a security group with SSH open to the internet; and the weakest
  password policy the API accepts.
- **`modules/fixed`** — the same resource addresses, remediated, plus the two
  account-level items CIS asks for that the vulnerable state lacked: a
  multi-region CloudTrail trail and a strong IAM password policy. Resource
  addresses match, so `make apply MODE=fixed` repairs the deployed lab in place
  and the plan diff reads as the fix list.
- **`scripts/scan.sh`** — runs Prowler against the account and writes one CSV.
- **`scripts/assess.py`** — reads the before and after CSVs, asserts each
  lab finding flipped from FAIL to PASS, and exits non-zero if any survived.
- **CI (GitHub Actions)** — runs without AWS credentials: `terraform validate`,
  unit tests for `assess.py`, and a Checkov pair that must flag the vuln module
  and pass the fixed one. That pair is the static before/after, re-run on every
  push.

## How to run it

Prerequisites, exactly: Terraform ≥ 1.5 (built on 1.14.1), `pipx` with Prowler
and Checkov installed, Python ≥ 3.11 with `pytest`, and AWS credentials for a
throwaway account (AdministratorAccess or broad read plus the remediation
writes; region `us-east-1` by default).

```
make init        # download the AWS provider
make before      # deploy the misconfigured lab, scan → evidence/before/prowler.csv
make after       # remediate the same resources, scan → evidence/after/prowler.csv
make prove       # assert every lab finding flipped FAIL → PASS
make destroy     # remove everything
```

`make test` runs the `assess.py` unit tests without touching AWS.

## What you'll see when it works

`make prove` prints one line per tracked check — its Prowler check ID, the
before status, the after status — and exits 0. If a misconfiguration survived
the remediation, it exits 1 and names the check that is still failing.

## Teardown

`make destroy` deletes the bucket, the security group, the trail and its audit
bucket, and restores the account-level settings. Nothing else is created, so
nothing else needs removing. Destroy the same day you deploy: the lab is priced
at roughly zero only while nothing lingers.

## Design decisions

**Decision: two modules (`vuln`, `fixed`) with matching resource addresses,
selected by a one-line source swap that `make apply MODE=...` makes for you.**
*Alternatives considered:* one module with a `secure` boolean per resource
(Terraform cannot put a variable in a module `source`); two separate states via
`-chdir` (the remediation would then destroy and recreate the lab instead of
repairing it in place).
*Why this one:* both modes share one Terraform state and the same resource
addresses, so switching from vuln to fixed updates the deployed lab in place
and `terraform plan` between the two modes reads as the fix list. The vuln
module also stays readable as a catalogue of mistakes. The cost is some
duplication between the modules, and `main.tf` is a generated file the Makefile
overwrites.

**Decision: the misconfigurations are all near-zero-cost resources (S3, a
security group, account settings) — no EC2 instances, no RDS.**
*Alternatives considered:* an unencrypted EBS volume or database for realism.
*Why this one:* the lab runs on a throwaway account with a spend budget. S3,
security groups and account settings bill nothing, and every CIS finding the
week is graded on can be produced with them. The cost is that findings that
need a running instance stay out of scope.

**Decision: GuardDuty stays off and CloudTrail ships to S3 only.**
*Alternatives considered:* switching on every CIS 3.x/4.x item in the fixed
module.
*Why this one:* GuardDuty's free trial ends in paid hourly charges and a KMS
customer-managed key costs $1 per month — wrong trade for a throwaway lab. One
multi-region trail with validated log files is free and is the CIS item
attackers actually care about. The remaining CIS items are listed as
limitations, not silently claimed.

**Decision: the proof is the scanner's own output, not a hand-written table.**
*Alternatives considered:* writing the remediation summary by hand.
*Why this one:* `assess.py` compares the two Prowler CSVs, so the report cannot
say a finding closed unless the scanner said so on the wire. The cost is that
the tracked checks live in one list in `assess.py` and must match Prowler's
check IDs.

## Limitations

- The fixed module leaves CIS AWS Benchmark items open on purpose: GuardDuty
  (paid after its trial), a KMS CMK for CloudTrail/S3 ($1/month), CloudTrail's
  CloudWatch and SNS delivery (ingestion cost), and root-account hygiene items
  the lab does not touch.
- Prowler is the graded scanner; ScoutSuite is run once for a second opinion and
  its HTML report is not committed (it is generated output).
- The lab exercises S3, EC2 security groups and IAM account settings. Findings
  that need other services (EBS, RDS, Lambda) are out of scope.

## Evidence

- `docs/report.md` — the before/after CSPM report (written from the scans).
- `evidence/before/prowler.csv`, `evidence/after/prowler.csv` — raw scanner
  output, committed.
- CI runs Checkov over both modules on every push: the vuln module must fail
  it, the fixed module must pass.

## What was learned

Written into the report once the scans have run: which findings the scanners
caught, which they disagreed on, and what the remediation actually cost in
plan diff.