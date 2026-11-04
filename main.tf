# Which module the lab deploys: ./modules/vuln (deliberately misconfigured)
# or ./modules/fixed (remediated). Terraform requires a static module source,
# so the mode is this one line; `make apply MODE=...` swaps it from modes/.
# Resource addresses are identical in both modules, so switching from vuln to
# fixed updates the deployed lab in place and `terraform plan` between the two
# modes reads as the fix list.

module "lab" {
  source   = "./modules/vuln"
  region   = var.region
  lab_name = var.lab_name
}