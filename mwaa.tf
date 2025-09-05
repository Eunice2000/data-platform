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
# MWAA Execution Role Policy (Full Permissions)
#########################
resource "aws_iam_role_policy" "mwaa_execution_role_policy" {
  name = "${var.mwaa_config.mwaa_name}-execution-role-policy"
  role = aws_iam_role.mwaa_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        # Access to each bucket
        for access in var.mwaa_config.s3_access : {
          Effect = "Allow"
          Action = access.actions
          Resource = [
            module.s3[access.bucket_key].s3_bucket_arn,
            "${module.s3[access.bucket_key].s3_bucket_arn}/*"
          ]
        }
      ],
      [
        # S3 Public Access Block
        {
          Effect = "Allow"
          Action = [
            "s3:GetAccountPublicAccessBlock",
            "s3:GetBucketPublicAccessBlock"
          ]
          Resource = "*"
        },
        # CloudWatch Logs
        {
          Effect = "Allow"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:GetLogEvents",
            "logs:GetLogGroupFields",
            "logs:DescribeLogGroups"
          ]
          Resource = "*"
        },
        # CloudWatch Metrics
        {
          Effect = "Allow"
          Action = ["cloudwatch:PutMetricData"]
          Resource = "*"
        },
        # SQS for Celery queues
        {
          Effect = "Allow"
          Action = [
            "sqs:SendMessage",
            "sqs:ReceiveMessage",
            "sqs:GetQueueUrl",
            "sqs:GetQueueAttributes",
            "sqs:DeleteMessage",
            "sqs:ChangeMessageVisibility"
          ]
          Resource = "arn:aws:sqs:${var.region}:${data.aws_caller_identity.current.account_id}:airflow-celery-*"
        },
        # KMS for environment & S3 encryption
        {
          Effect = "Allow"
          Action = [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:GenerateDataKey*",
            "kms:DescribeKey"
          ]
          Resource = "*"
        },
        # MWAA Metrics
        {
          Effect = "Allow"
          Action = ["airflow:PublishMetrics"]
          Resource = "arn:aws:airflow:${var.region}:${data.aws_caller_identity.current.account_id}:environment/${var.mwaa_config.mwaa_name}"
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

  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.bucket_encryption,
    aws_iam_role_policy.mwaa_execution_role_policy
  ]
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
        Effect = "Allow"
        Action = [
          "airflow:GetEnvironment",
          "airflow:ListEnvironments",
          "airflow:CreateWebLoginToken"
        ]
        Resource = "*"
      }
    ]
  })
}
