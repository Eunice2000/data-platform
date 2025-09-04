variable "vpc_config" {
  description = "VPC configurations"
  type = object({
    name            = string
    cidr            = string
    azs             = list(string)
    public_subnets  = list(string)
    private_subnets = list(string)
    enable_nat      = bool
    default_security_group_egress = list(object({
      from_port   = number
      to_port     = number
      protocol    = string
      cidr_blocks = string
    }))
  })
}

variable "s3_config" {
  description = "s3 configurations"
  type = map(object({
    bucket_name      = string
    force_destroy    = bool
    enable_lifecycle = bool
    lifecycle_config = optional(object({
      standard_ia_days     = optional(number, 30)
      glacier_days         = optional(number, 90)
      deep_archive_days    = optional(number, 365)
      expiration_days      = optional(number, 3650)
      multipart_abort_days = optional(number, 7)
    }), {})
    folders = list(string)
  }))
}


variable "tags" {
  description = "Tags to apply to resources"
}
