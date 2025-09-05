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
# MWAA Execution Role Policy (Dynamic S3 Access per Bucket)
#########################
resource "aws_iam_role_policy" "mwaa_s3_access" {
  for_each = {
    for idx, access in var.mwaa_config.s3_access :
    idx => access
  }

  role = aws_iam_role.mwaa_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = each.value.actions
        Resource = [
          module.s3[each.value.bucket_key].s3_bucket_arn,
          "${module.s3[each.value.bucket_key].s3_bucket_arn}/*"
        ]
      }
    ]
  })
}

#########################
# Additional Permissions (CloudWatch, EC2, SQS, KMS)
#########################
resource "aws_iam_role_policy" "mwaa_execution_additional" {
  name = "${var.mwaa_config.mwaa_name}-execution-additional"
  role = aws_iam_role.mwaa_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3 public access block check
      {
        Effect = "Allow"
        Action = [
          "s3:GetAccountPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "*"
      },
      # AWS-managed KMS permissions
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:ViaService" = [
              "sqs.${var.region}.amazonaws.com",
              "s3.${var.region}.amazonaws.com"
            ]
          }
        }
      },
      # CloudWatch permissions
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:GetLogEvents",
          "logs:GetLogRecord"
        ]
        Resource = "arn:aws:logs:*:*:log-group:airflow-${var.mwaa_config.mwaa_name}-*"
      },
      {
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
      },
      # EC2 read-only permissions
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      # SQS permissions
      {
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
          "sqs:SendMessage"
        ]
        Resource = "arn:aws:sqs:${var.region}:*:airflow-celery-*"
      },
      # Airflow metrics
      {
        Effect = "Allow"
        Action   = ["airflow:PublishMetrics"]
        Resource = "arn:aws:airflow:${var.region}:${var.account_id}:environment/${var.mwaa_config.mwaa_name}"
      }
    ]
  })
}

#########################
# MWAA Security Group
#########################
resource "aws_security_group" "mwaa_sg" {
  name        = "${var.mwaa_config.mwaa_name}-sg"
  description = "Security group for MWAA environment"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.mwaa_config.mwaa_name}-sg" })
}

#########################
# VPC Endpoint for S3
#########################
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = module.vpc.private_route_table_ids

  tags = merge(var.tags, { Name = "${var.vpc_config.name}-s3-endpoint" })
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
    security_group_ids = [aws_security_group.mwaa_sg.id]
  }

  logging_configuration {
    dag_processing_logs {
      enabled   = true
      log_level = "INFO"
    }

    scheduler_logs {
      enabled   = true
      log_level = "INFO"
    }

    task_logs {
      enabled   = true
      log_level = "INFO"
    }

    webserver_logs {
      enabled   = true
      log_level = "INFO"
    }

    worker_logs {
      enabled   = true
      log_level = "INFO"
    }
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
    aws_vpc_endpoint.s3
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
