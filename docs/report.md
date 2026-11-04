# Before/after CSPM report

The lab deployed a deliberately misconfigured AWS environment, scanned it with
three tools, remediated it in place, and scanned again. This is the proof that
the posture was cleaned up: every tracked finding went from fail to pass, and
nothing else got worse.

Account `198811874138` (a throwaway), region `us-east-1`, scanned 2026-11-04.

## Result in one line

- **Prowler:** account findings went from 98 fail / 70 pass to 91 fail /
  100 pass. All 18 tracked lab checks flipped fail → pass; `make prove` exits 0.
- **AWS Config:** all 5 managed rules went from `NON_COMPLIANT` to `COMPLIANT`.
- **ScoutSuite:** every lab misconfiguration it flagged in the vulnerable state
  was gone in the fixed state (one accepted exception, below).

The remaining Prowler fails are account-wide items the lab does not touch (root
account hygiene, access-key rotation, and so on), not lab resources.

## The 18 tracked findings

Each is a Prowler check, its CIS AWS Foundations Benchmark v4.0.1 number where
one exists, the before and after status, and the one-line fix. All of these are
`modules/vuln` → `modules/fixed` in one Terraform state; the plan diff between
the two modes is the fix list.

| Prowler check | CIS 4.0.1 | Sev | Before | After | Fix |
|---|---|---|---|---|---|
| `s3_bucket_public_access` | — | crit | FAIL | PASS | Remove the public-read ACL |
| `s3_bucket_public_list_acl` | — | crit | FAIL | PASS | Remove the public-read ACL |
| `s3_bucket_level_public_access_block` | 2.1.4 | high | FAIL | PASS | Turn the bucket block on |
| `s3_account_level_public_access_blocks` | 2.1.4 | high | FAIL | PASS | Turn the account block on |
| `s3_bucket_acl_prohibited` | — | med | FAIL | PASS | Set ownership to BucketOwnerEnforced (ACLs off) |
| `s3_bucket_object_versioning` | — | med | FAIL | PASS | Enable versioning |
| `s3_bucket_secure_transport_policy` | 2.1.1 | med | FAIL | PASS | Deny non-HTTPS with a bucket policy |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | 5.3 | high | FAIL | PASS | Remove the 0.0.0.0/0 SSH rule |
| `iam_password_policy_minimum_length_14` | 1.8 | med | FAIL | PASS | Minimum length 14 |
| `iam_password_policy_lowercase` | — | low | FAIL | PASS | Require a lowercase letter |
| `iam_password_policy_uppercase` | — | med | FAIL | PASS | Require an uppercase letter |
| `iam_password_policy_number` | — | med | FAIL | PASS | Require a digit |
| `iam_password_policy_symbol` | — | med | FAIL | PASS | Require a symbol |
| `iam_password_policy_reuse_24` | 1.9 | med | FAIL | PASS | Prevent reuse of the last 24 |
| `iam_password_policy_expires_passwords_within_90_days_or_less` | — | med | FAIL | PASS | Expire after 90 days |
| `cloudtrail_multi_region_enabled` | 3.1 | high | FAIL | PASS | Create a multi-region trail |
| `cloudtrail_multi_region_enabled_logging_management_events` | — | low | FAIL | PASS | Log management events |
| `cloudtrail_log_file_validation_enabled` | 3.2 | med | absent | PASS | Enable log-file validation on the trail |

The last row is an "added" check: with no trail in the vulnerable state,
Prowler has nothing to report on, so it first appears in the after scan. The
checks with a dash under CIS are Prowler best-practice checks, or password-
complexity items that CIS kept in v1.2 and dropped from v4.0; they still map the
lab's deliberate mistakes, so the lab tracks them.

## AWS Config: the same posture, from a different tool

Five AWS managed rules, recorded against the lab's resource types only, then the
recorder, delivery channel, bucket and rules deleted in the same session.
`scripts/config.sh` sets them up and tears them down.

| Config rule | Source identifier | Before | After |
|---|---|---|---|
| `seceng-s3-bucket-public-read-prohibited` | `S3_BUCKET_PUBLIC_READ_PROHIBITED` | NON_COMPLIANT | COMPLIANT |
| `seceng-s3-bucket-ssl-requests-only` | `S3_BUCKET_SSL_REQUESTS_ONLY` | NON_COMPLIANT | COMPLIANT |
| `seceng-restricted-ssh` | `INCOMING_SSH_DISABLED` | NON_COMPLIANT | COMPLIANT |
| `seceng-iam-password-policy` | `IAM_PASSWORD_POLICY` | NON_COMPLIANT | COMPLIANT |
| `seceng-cloudtrail-enabled` | `CLOUD_TRAIL_ENABLED` | NON_COMPLIANT | COMPLIANT |

Three things the Config run taught, that a single Prowler scan does not show:

- **A managed rule is only as strict as its parameters.** With no parameters,
  `IAM_PASSWORD_POLICY` checks only that *a* policy exists, so it called the
  weak 6-character policy `COMPLIANT`. Set to the CIS values (length 14, all
  four character classes, reuse 24, 90-day expiry) it correctly fails the weak
  policy. Prowler bakes the CIS thresholds in; Config makes you choose them.
- **Config scans its own plumbing.** The first fixed-state run read
  `NON_COMPLIANT` for the S3 SSL rule — not because of a lab bucket, but because
  Config's own delivery bucket had no HTTPS-only policy and is in the rule's
  scope. Hardening that bucket (it should be hardened anyway) cleared it.
- **Config is eventually consistent.** Its rules evaluate the last *recorded*
  configuration. Right after remediation, a rule can still read the pre-fix
  state until the recorder catches up; Prowler, which reads the live API, does
  not have this lag.

## ScoutSuite: the second opinion

ScoutSuite ran once per state (its HTML report is generated output, not
committed). On the lab's deliberate mistakes it agrees with Prowler exactly:

| ScoutSuite finding | Vulnerable | Fixed |
|---|---|---|
| `s3-bucket-AllUsers-read` | 1 | 0 |
| `s3-bucket-allowing-cleartext` | flagged | 0 |
| `s3-bucket-no-versioning` | flagged | 0 |
| `ec2-security-group-opens-SSH-port-to-all` | 1 | 0 |
| `iam-password-policy-minimum-length` | flagged | 0 |
| `iam-password-policy-no-expiration` | flagged | 0 |
| `iam-password-policy-reuse-enabled` | flagged | 0 |
| `cloudtrail-not-configured` | flagged | 0 |

Where the tools differ:

- **ScoutSuite reports more account-wide noise.** It flags the default security
  group's rules, EBS default encryption off, recent root-account use, and the
  `AdministratorAccess` managed policy. These are real, but they are account
  hygiene the lab does not set out to fix, so they are not tracked.
- **The unused security group stays flagged, in all three tools.** The fixed
  group has no rules, but it is attached to nothing, because the lab runs no
  instances. ScoutSuite (`ec2-unused-security-group`), Prowler and Checkov
  (`CKV2_AWS_5`) all note it. It is an accepted scope limit, not a miss.

## Accepted limitations

These appear as new fails in the after scan because the trail did not exist
before. `scripts/assess.py` lists them as accepted on cost, not failures:

| Prowler check | CIS 4.0.1 | Why accepted |
|---|---|---|
| `cloudtrail_kms_encryption_enabled` | 3.5 | A KMS customer-managed key costs ~$1/month |
| `cloudtrail_logs_s3_bucket_access_logging_enabled` | 3.4 | No S3 access logging |
| `cloudtrail_cloudwatch_logging_enabled` | — | Trail ships to S3 only, no CloudWatch Logs |
| `cloudtrail_insights_exist` | — | Insights is billed per event analysed |
| `cloudtrail_bucket_requires_mfa_delete` | — | MFA delete can only be set by the root user |

GuardDuty stays off for the same reason (paid after its trial). The one
multi-region trail with log-file validation — free, and the CIS item attackers
care about most — is the part that is turned on.

## Cost and teardown

Every resource is S3, a security group, or an account setting, which bill
nothing, plus a few hours of a second copy of management events in CloudTrail
and a handful of Config evaluations and recordings. Total well under $5.
`make destroy` removed all 17 resources; the account public access block and
password policy, both unset before the lab, were returned to unset.
`evidence/baseline.txt` and `evidence/teardown.txt` show the account before and
after, identical. Nothing is left deployed.
