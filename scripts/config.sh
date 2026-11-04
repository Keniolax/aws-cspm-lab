#!/usr/bin/env bash
# AWS Config as a second posture check, run once against the vuln state and
# once against the fixed state, then torn down in the same session. Config
# bills per recorded item and per rule evaluation, so this records only the
# lab's resource types and deletes the recorder, the delivery channel, its
# bucket and the rules when done. Keep the deployed window short.
#
# usage:
#   scripts/config.sh setup     <account-id> <region>
#   scripts/config.sh evaluate
#   scripts/config.sh capture   <output-file>
#   scripts/config.sh teardown  <account-id> <region>
set -euo pipefail

cmd="${1:?usage: config.sh setup|evaluate|capture|teardown ...}"
region="${AWS_REGION:-us-east-1}"

recorder="seceng-cspm-lab-recorder"
channel="seceng-cspm-lab-channel"
# Managed rules keyed by rule name -> source identifier. The first three are
# change-triggered on a recorded resource type; the last two are periodic and
# evaluate the account on their own.
declare -A RULES=(
  [seceng-s3-bucket-public-read-prohibited]="S3_BUCKET_PUBLIC_READ_PROHIBITED"
  [seceng-s3-bucket-ssl-requests-only]="S3_BUCKET_SSL_REQUESTS_ONLY"
  [seceng-restricted-ssh]="INCOMING_SSH_DISABLED"
  [seceng-iam-password-policy]="IAM_PASSWORD_POLICY"
  [seceng-cloudtrail-enabled]="CLOUD_TRAIL_ENABLED"
)

config_bucket() { echo "seceng-cspm-lab-config-$1"; }

setup() {
  local acct="${1:?account id}" reg="${2:?region}"
  local bucket; bucket="$(config_bucket "$acct")"

  echo "config: ensuring the Config service-linked role exists"
  aws iam create-service-linked-role --aws-service-name config.amazonaws.com \
    >/dev/null 2>&1 || true
  local role_arn="arn:aws:iam::${acct}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

  echo "config: creating delivery bucket $bucket"
  aws s3api create-bucket --bucket "$bucket" --region "$reg" \
    --tagging "lab=seceng-bootcamp-week-10" >/dev/null 2>&1 || \
    aws s3api create-bucket --bucket "$bucket" --region "$reg" >/dev/null 2>&1 || true
  aws s3api put-bucket-tagging --bucket "$bucket" \
    --tagging 'TagSet=[{Key=lab,Value=seceng-bootcamp-week-10}]' >/dev/null 2>&1 || true

  # Config must be allowed to check the bucket ACL and write objects.
  local policy
  policy=$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid":"AWSConfigBucketPermissionsCheck","Effect":"Allow",
     "Principal":{"Service":"config.amazonaws.com"},
     "Action":["s3:GetBucketAcl","s3:ListBucket"],
     "Resource":"arn:aws:s3:::${bucket}"},
    {"Sid":"AWSConfigBucketDelivery","Effect":"Allow",
     "Principal":{"Service":"config.amazonaws.com"},
     "Action":"s3:PutObject",
     "Resource":"arn:aws:s3:::${bucket}/AWSLogs/${acct}/Config/*",
     "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}
  ]
}
JSON
)
  aws s3api put-bucket-policy --bucket "$bucket" --policy "$policy"

  echo "config: creating the recorder (S3, security groups, trails only)"
  aws configservice put-configuration-recorder \
    --configuration-recorder "name=${recorder},roleARN=${role_arn}" \
    --recording-group 'allSupported=false,includeGlobalResourceTypes=false,resourceTypes=["AWS::S3::Bucket","AWS::EC2::SecurityGroup","AWS::CloudTrail::Trail"]'

  aws configservice put-delivery-channel \
    --delivery-channel "name=${channel},s3BucketName=${bucket}"

  aws configservice start-configuration-recorder --configuration-recorder-name "$recorder"

  echo "config: creating ${#RULES[@]} managed rules"
  for name in "${!RULES[@]}"; do
    local src="${RULES[$name]}"
    local scope=""
    case "$src" in
      S3_BUCKET_PUBLIC_READ_PROHIBITED|S3_BUCKET_SSL_REQUESTS_ONLY)
        scope=',"Scope":{"ComplianceResourceTypes":["AWS::S3::Bucket"]}' ;;
      INCOMING_SSH_DISABLED)
        scope=',"Scope":{"ComplianceResourceTypes":["AWS::EC2::SecurityGroup"]}' ;;
    esac
    local maxfreq=""
    case "$src" in
      IAM_PASSWORD_POLICY|CLOUD_TRAIL_ENABLED)
        maxfreq='"MaximumExecutionFrequency":"One_Hour",' ;;
    esac
    # IAM_PASSWORD_POLICY with no parameters only checks that a policy exists.
    # Parameterise it to the CIS values so it catches the weak 6-char policy,
    # matching what Prowler flags.
    local params=""
    if [ "$src" = "IAM_PASSWORD_POLICY" ]; then
      params=',"InputParameters":"{\"RequireUppercaseCharacters\":\"true\",\"RequireLowercaseCharacters\":\"true\",\"RequireSymbols\":\"true\",\"RequireNumbers\":\"true\",\"MinimumPasswordLength\":\"14\",\"PasswordReusePrevention\":\"24\",\"MaxPasswordAge\":\"90\"}"'
    fi
    aws configservice put-config-rule --config-rule "$(cat <<JSON
{"ConfigRuleName":"${name}",
 ${maxfreq}"Source":{"Owner":"AWS","SourceIdentifier":"${src}"}${scope}${params}}
JSON
)" >/dev/null
  done
  echo "config: setup complete"
}

evaluate() {
  echo "config: starting an on-demand evaluation of all lab rules"
  aws configservice start-config-rules-evaluation \
    --config-rule-names "${!RULES[@]}" >/dev/null 2>&1 || true
  echo "config: waiting for evaluations to settle"
  sleep 90
}

capture() {
  local out="${1:?output file}"
  {
    echo "=== AWS Config rule compliance, $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    for name in "${!RULES[@]}"; do
      local state
      state=$(aws configservice describe-compliance-by-config-rule \
        --config-rule-names "$name" \
        --query 'ComplianceByConfigRules[0].Compliance.ComplianceType' \
        --output text 2>/dev/null || echo "UNKNOWN")
      printf "%-45s %-35s %s\n" "$name" "${RULES[$name]}" "$state"
    done
  } | tee "$out"
}

teardown() {
  local acct="${1:?account id}" reg="${2:?region}"
  local bucket; bucket="$(config_bucket "$acct")"
  echo "config: deleting rules"
  for name in "${!RULES[@]}"; do
    aws configservice delete-config-rule --config-rule-name "$name" >/dev/null 2>&1 || true
  done
  echo "config: stopping and deleting the recorder and delivery channel"
  aws configservice stop-configuration-recorder --configuration-recorder-name "$recorder" >/dev/null 2>&1 || true
  aws configservice delete-delivery-channel --delivery-channel-name "$channel" >/dev/null 2>&1 || true
  aws configservice delete-configuration-recorder --configuration-recorder-name "$recorder" >/dev/null 2>&1 || true
  echo "config: emptying and deleting $bucket"
  aws s3 rm "s3://${bucket}" --recursive >/dev/null 2>&1 || true
  aws s3api delete-bucket --bucket "$bucket" --region "$reg" >/dev/null 2>&1 || true
  echo "config: teardown complete (service-linked role left in place; it is free)"
}

case "$cmd" in
  setup)    setup "${2:?account id}" "${3:-$region}" ;;
  evaluate) evaluate ;;
  capture)  capture "${2:?output file}" ;;
  teardown) teardown "${2:?account id}" "${3:-$region}" ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
