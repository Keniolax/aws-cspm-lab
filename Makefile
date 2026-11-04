# Week 10 lab: misconfigure, scan, remediate, re-scan, prove the difference.
# All targets are credential-free to READ about, but apply/scan need a real
# AWS account (the bootcamp throwaway).

MODE ?= vuln

.PHONY: init apply destroy before after prove test fmt

init:
	terraform init

apply:
	cp modes/$(MODE).tf main.tf
	terraform init -input=false
	terraform apply -auto-approve

destroy:
	terraform destroy -auto-approve

# Deploy the broken version and scan it: evidence/before/prowler.csv
before:
	$(MAKE) apply MODE=vuln
	./scripts/scan.sh vuln evidence/before

# Remediate the same resources and scan again: evidence/after/prowler.csv
after:
	$(MAKE) apply MODE=fixed
	./scripts/scan.sh fixed evidence/after

# Assert the before/after CSVs show the misconfigurations closed.
prove:
	python3 scripts/assess.py evidence/before evidence/after

test:
	python3 -m pytest scripts/ -q

fmt:
	terraform fmt -recursive