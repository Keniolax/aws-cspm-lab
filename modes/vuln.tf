# Copied to main.tf by `make apply MODE=vuln`.

module "lab" {
  source   = "./modules/vuln"
  region   = var.region
  lab_name = var.lab_name
}