# Copied to main.tf by `make apply MODE=fixed`.

module "lab" {
  source   = "./modules/fixed"
  region   = var.region
  lab_name = var.lab_name
}