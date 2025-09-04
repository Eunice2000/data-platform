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
# MWAA Execution Role Policy (Optimized - No Over-Provisioning)
#########################
resource "aws_iam_role_policy" "mwaa_execution_policy" {
  name = "${var.mwaa_config.mwaa_name}-execution-policy"
  role = aws_iam_role.mwaa_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3 permissions (read-only only)
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject*",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration"
        ]
        Resource = [
          module.s3[var.mwaa_config.s3_bucket_key].s3_bucket_arn,
          "${module.s3[var.mwaa_config.s3_bucket_key].s3_bucket_arn}/*"
        ]
      },
      # S3 public access block check (required)
      {
        Effect = "Allow"
        Action = [
          "s3:GetAccountPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "*"
      },

      # AWS-managed KMS permissions (optimized)
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

      # CloudWatch permissions (required)
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

      # EC2 networking permissions (read-only only - optimized)
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

      # SQS permissions (required for Celery executor)
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

      # Airflow metrics permission (required)
      {
        Effect = "Allow"
        Action = [
          "airflow:PublishMetrics"
        ]
        Resource = "arn:aws:airflow:${var.region}:${data.aws_caller_identity.current.account_id}:environment/${var.mwaa_config.mwaa_name}"
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

  # Self-referencing inbound rules (required for MWAA components)
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.mwaa_config.mwaa_name}-sg" })
}

#########################
# VPC Endpoints (Only essential S3 endpoint)
#########################
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = module.vpc.private_route_table_ids

  tags = merge(var.tags, { Name = "${var.vpc_config.name}-s3-endpoint" })
}

#########################
# MWAA Environment (Using AWS-managed KMS)
#########################
resource "aws_mwaa_environment" "mwaa" {
  name               = var.mwaa_config.mwaa_name
  execution_role_arn = aws_iam_role.mwaa_execution_role.arn
  source_bucket_arn  = module.s3[var.mwaa_config.s3_bucket_key].s3_bucket_arn
  dag_s3_path        = var.mwaa_config.s3_dags_path
  airflow_version    = "2.8.1"

  # Note: kms_key parameter is omitted to use AWS-managed KMS

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

  # Airflow configuration options
  airflow_configuration_options = {
    "core.lazy_load_plugins"       = "False"
    "webserver.expose_config"      = "True"
    "core.default_task_retries"    = "3"
    "core.parallelism"             = "40"
    "scheduler.catchup_by_default" = "False"
  }

  tags = merge(var.tags, {
    Name = var.mwaa_config.mwaa_name,
    Team = "ReportingAndAnalytics"
  })

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

# Attach inline policy for MWAA UI access
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

# (Optional) Access keys for programmatic use
resource "aws_iam_access_key" "mwaa_ui_user_keys" {
  user = aws_iam_user.mwaa_ui_user.name
}
