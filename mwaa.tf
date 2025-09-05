#########################
# Local Values
#########################
locals {
  plugins_s3_path      = var.mwaa_config.enable_plugins ? "plugins/" : null
  requirements_s3_path = var.mwaa_config.enable_requirements ? "requirements/requirements.txt" : null
}

#########################
# MWAA Execution Role
#########################
resource "aws_iam_role" "mwaa_execution_role" {
  name = "${var.mwaa_config.mwaa_name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = [
          "airflow.amazonaws.com",
          "airflow-env.amazonaws.com"
        ]
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, { Name = "${var.mwaa_config.mwaa_name}-execution-role" })
}

#########################
# MWAA Execution Role Policy (S3 + Public Access Block)
#########################
resource "aws_iam_role_policy" "mwaa_s3_access" {
  for_each = { for idx, access in var.mwaa_config.s3_access : idx => access }

  role = aws_iam_role.mwaa_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        # Access to each bucket
        for access in [each.value] : {
          Effect   = "Allow"
          Action   = access.actions
          Resource = [
            module.s3[access.bucket_key].s3_bucket_arn,
            "${module.s3[access.bucket_key].s3_bucket_arn}/*"
          ]
        }
      ],
      [
        # Allow MWAA to check public access block
        {
          Effect = "Allow"
          Action = ["s3:GetAccountPublicAccessBlock"]
          Resource = "*"
        }
      ]
    )
  })
}

#########################
# MWAA Environment
#########################
resource "aws_mwaa_environment" "mwaa" {
  name                 = var.mwaa_config.mwaa_name
  execution_role_arn   = aws_iam_role.mwaa_execution_role.arn
  source_bucket_arn    = module.s3[var.mwaa_config.s3_bucket_key].s3_bucket_arn
  dag_s3_path          = var.mwaa_config.s3_dags_path
  airflow_version      = var.mwaa_config.airflow_version
  plugins_s3_path      = local.plugins_s3_path
  requirements_s3_path = local.requirements_s3_path

  network_configuration {
    subnet_ids         = slice(module.vpc.private_subnets, 0, 2)
    security_group_ids = [module.vpc.default_security_group_id]
  }

  airflow_configuration_options = {
    "core.lazy_load_plugins"       = "False"
    "webserver.expose_config"      = "True"
    "core.default_task_retries"    = "3"
    "core.parallelism"             = "40"
    "scheduler.catchup_by_default" = "False"
  }

  tags = merge(var.tags, { Name = var.mwaa_config.mwaa_name })

  # Avoid creation issues if S3 bucket does not exist yet
  depends_on = [aws_iam_role_policy.mwaa_s3_access]
}

#########################
# IAM User for Airflow UI Access
#########################
resource "aws_iam_user" "mwaa_ui_user" {
  name = "${var.mwaa_config.mwaa_name}-ui-user"
  tags = merge(var.tags, { Name = "${var.mwaa_config.mwaa_name}-ui-user" })
}

resource "aws_iam_user_policy" "mwaa_ui_user_policy" {
  name = "${var.mwaa_config.mwaa_name}-ui-user-policy"
  user = aws_iam_user.mwaa_ui_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "airflow:GetEnvironment",
          "airflow:ListEnvironments",
          "airflow:CreateWebLoginToken"
        ]
        Resource = "*"
      }
    ]
  })
}
