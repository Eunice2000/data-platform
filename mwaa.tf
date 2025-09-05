#########################
# Local Values
#########################
locals {
  # S3 paths for plugins and requirements
  plugins_s3_path      = var.mwaa_config.enable_plugins ? "plugins/" : null
  requirements_s3_path = var.mwaa_config.enable_requirements ? "requirements/requirements.txt" : null

  # Determine the execution role ARN: use created IAM role or provided ARN
  execution_role_arn = var.mwaa_config.create_iam_role ? aws_iam_role.mwaa[0].arn : var.mwaa_config.execution_role_arn

  # Determine security group IDs: include MWAA SG if creating, else use default VPC SG
  security_group_ids = (
    var.mwaa_config.create_security_group
    ? concat([aws_security_group.mwaa[0].id], var.mwaa_config.security_group_ids)
    : concat([module.vpc.default_security_group_id], var.mwaa_config.security_group_ids)
  )

  # Default Airflow configuration options
  default_airflow_configuration_options = {
    "logging.logging_level" = "INFO"
  }

  # Merge user-provided Airflow config with defaults
  airflow_configuration_options = merge(
    local.default_airflow_configuration_options,
    var.mwaa_config.airflow_configuration_options != null ? var.mwaa_config.airflow_configuration_options : {}
  )

  # Additional IAM policies to attach if creating the role
  iam_role_additional_policies = {
    for k, v in var.mwaa_config.iam_role_additional_policies : k => v
    if var.mwaa_config.create_iam_role
  }

  # Source bucket ARN (lookup from S3 module using the configured key)
  source_bucket_arn = module.s3[var.mwaa_config.s3_bucket_key].s3_bucket_arn
}

#########################
# MWAA IAM Role
#########################
resource "aws_iam_role" "mwaa" {
  count = var.mwaa_config.create_iam_role ? 1 : 0

  name                  = var.mwaa_config.iam_role_name != null ? var.mwaa_config.iam_role_name : null
  name_prefix           = var.mwaa_config.iam_role_name != null ? null : "${var.mwaa_config.mwaa_name}-execution-role-"
  description           = "MWAA IAM Role"
  assume_role_policy    = data.aws_iam_policy_document.mwaa_assume.json
  force_detach_policies = var.mwaa_config.force_detach_policies
  path                  = var.mwaa_config.iam_role_path
  permissions_boundary  = var.mwaa_config.iam_role_permissions_boundary

  tags = merge(var.tags, { Name = "${var.mwaa_config.mwaa_name}-execution-role" })
}

resource "aws_iam_role_policy" "mwaa" {
  count = var.mwaa_config.create_iam_role ? 1 : 0

  name_prefix = "${var.mwaa_config.mwaa_name}-execution-role-"
  role        = aws_iam_role.mwaa[0].id
  policy      = data.aws_iam_policy_document.mwaa.json
}

resource "aws_iam_role_policy_attachment" "mwaa" {
  for_each   = local.iam_role_additional_policies
  policy_arn = each.value
  role       = aws_iam_role.mwaa[0].id
}

#########################
# MWAA Environment
#########################
resource "aws_mwaa_environment" "mwaa" {
  name                          = var.mwaa_config.mwaa_name
  execution_role_arn            = local.execution_role_arn
  source_bucket_arn             = local.source_bucket_arn
  dag_s3_path                   = var.mwaa_config.s3_dags_path
  airflow_version               = var.mwaa_config.airflow_version
  plugins_s3_path               = local.plugins_s3_path
  requirements_s3_path          = local.requirements_s3_path
  airflow_configuration_options = local.airflow_configuration_options

  network_configuration {
    subnet_ids         = slice(module.vpc.private_subnets, 0, 2)
    security_group_ids = local.security_group_ids
  }

  logging_configuration {
    dag_processing_logs {
      enabled   = try(var.mwaa_config.logging_configuration.dag_processing_logs.enabled, true)
      log_level = try(var.mwaa_config.logging_configuration.dag_processing_logs.log_level, "DEBUG")
    }

    scheduler_logs {
      enabled   = try(var.mwaa_config.logging_configuration.scheduler_logs.enabled, true)
      log_level = try(var.mwaa_config.logging_configuration.scheduler_logs.log_level, "INFO")
    }

    task_logs {
      enabled   = try(var.mwaa_config.logging_configuration.task_logs.enabled, true)
      log_level = try(var.mwaa_config.logging_configuration.task_logs.log_level, "WARNING")
    }

    webserver_logs {
      enabled   = try(var.mwaa_config.logging_configuration.webserver_logs.enabled, true)
      log_level = try(var.mwaa_config.logging_configuration.webserver_logs.log_level, "ERROR")
    }

    worker_logs {
      enabled   = try(var.mwaa_config.logging_configuration.worker_logs.enabled, true)
      log_level = try(var.mwaa_config.logging_configuration.worker_logs.log_level, "CRITICAL")
    }
  }

  tags = merge(var.tags, { Name = var.mwaa_config.mwaa_name })
}

#########################
# MWAA Security Group
#########################
resource "aws_security_group" "mwaa" {
  count       = var.mwaa_config.create_security_group ? 1 : 0
  name_prefix = "mwaa-"
  description = "Security group for MWAA environment"
  vpc_id      = module.vpc.vpc_id

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(var.tags, { Name = "${var.mwaa_config.mwaa_name}-ui-user" })
}

resource "aws_security_group_rule" "mwaa_sg_inbound" {
  count              = var.mwaa_config.create_security_group ? 1 : 0
  type               = "ingress"
  from_port          = 0
  to_port            = 0
  protocol           = "-1"
  source_security_group_id = aws_security_group.mwaa[0].id
  security_group_id        = aws_security_group.mwaa[0].id
  description              = "Amazon MWAA inbound access"
}

resource "aws_security_group_rule" "mwaa_sg_inbound_vpn" {
  count = var.mwaa_config.create_security_group && length(var.mwaa_config.source_cidr) > 0 ? 1 : 0
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = var.mwaa_config.source_cidr
  security_group_id = aws_security_group.mwaa[0].id
  description       = "VPN / custom CIDR access for Airflow UI"
}

resource "aws_security_group_rule" "mwaa_sg_outbound" {
  count = var.mwaa_config.create_security_group ? 1 : 0
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.mwaa[0].id
  description       = "Allow all outbound traffic from MWAA"
}
