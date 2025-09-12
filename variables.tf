#########################
# VPC Configuration
#########################
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

#########################
# S3 Configuration
#########################
variable "s3_config" {
  description = "S3 bucket configurations"
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

#########################
# MWAA Configuration
#########################
variable "mwaa_config" {
  description = "MWAA configurations including IAM role settings, logging, plugins, security groups, and KMS"
  type = object({
    # MWAA basic settings
    mwaa_name     = string
    s3_dags_path  = string
    s3_bucket_key = string
    s3_access = list(object({
      bucket_key = string
      actions    = list(string)
    }))
    enable_plugins      = optional(bool, false)
    enable_requirements = optional(bool, false)
    airflow_version     = optional(string, "2.8.1")

    # IAM role settings
    create_iam_role               = optional(bool, false)
    iam_role_name                 = optional(string, null)
    additional_principal_arns     = optional(list(string), [])
    iam_role_permissions_boundary = optional(string, null)
    force_detach_policies         = optional(bool, false)
    iam_role_additional_policies  = optional(map(string), {})
    iam_role_path                 = optional(string, "/")
    execution_role_arn            = optional(string, null)

    # Logging configuration
    logging_configuration = optional(any, null)

    # Security groups
    create_security_group = optional(bool, false)
    security_group_ids    = optional(list(string), [])
    source_cidr           = optional(list(string), []) # For Airflow UI access if SG created

    # New optional attributes
    airflow_configuration_options = optional(map(string), {}) # for Airflow config

  })
}



#########################
# Tags
#########################
variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
