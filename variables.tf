variable "region" {
  description = "AWS region the lab deploys into. The bootcamp account works in us-east-1."
  type        = string
  default     = "us-east-1"
}

variable "lab_name" {
  description = "Prefix for resource names. The account ID is appended to keep bucket names unique."
  type        = string
  default     = "seceng-cspm-lab"
}