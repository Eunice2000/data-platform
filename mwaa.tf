
#########################
# KMS Key for Encryption
#########################
resource "aws_kms_key" "mwaa_kms" {
  description             = "KMS key for MWAA environment ${var.mwaa_config.mwaa_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.mwaa_kms_policy.json

  tags = merge(var.tags, { Name = "${var.mwaa_config.mwaa_name}-kms-key" })
}

resource "aws_kms_alias" "mwaa_kms" {
  name          = "alias/${var.mwaa_config.mwaa_name}-mwaa-key"
  target_key_id = aws_kms_key.mwaa_kms.key_id
}

data "aws_iam_policy_document" "mwaa_kms_policy" {
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "Allow MWAA to use the key"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
      "kms:Encrypt"
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]
    }
  }

  statement {
    sid    = "Allow CloudWatch Logs to use the key"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
  }
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
# MWAA Execution Role Policy (FIXED - Added missing permissions)
#########################
resource "aws_iam_role_policy" "mwaa_execution_policy" {
  name = "${var.mwaa_config.mwaa_name}-execution-policy"
  role = aws_iam_role.mwaa_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Airflow permissions
      {
        Effect = "Allow"
        Action = "airflow:*"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "*"
        Condition = {
          StringLike = {
            "iam:PassedToService" = "airflow.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = "iam:ListRoles"
        Resource = "*"
      },
      
      # S3 permissions for existing buckets
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject*",
          "s3:PutObject*",
          "s3:DeleteObject*",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning"
        ]
        Resource = [
          module.s3[var.mwaa_config.s3_bucket_key].s3_bucket_arn,
          "${module.s3[var.mwaa_config.s3_bucket_key].s3_bucket_arn}/*"
        ]
      },
      # CRITICAL FIX: Added missing permission for S3 public access block check
      {
        Effect = "Allow"
        Action = [
          "s3:GetAccountPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "*"
      },
      
      # KMS permissions
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
          "kms:Encrypt"
        ]
        Resource = aws_kms_key.mwaa_kms.arn
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
        Effect = "Allow"
        Action = "cloudwatch:PutMetricData"
        Resource = "*"
      },
      
      # EC2 networking permissions
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
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
# MWAA Environment
#########################
resource "aws_mwaa_environment" "mwaa" {
  name                 = var.mwaa_config.mwaa_name
  execution_role_arn   = aws_iam_role.mwaa_execution_role.arn
  source_bucket_arn    = module.s3[var.mwaa_config.s3_bucket_key].s3_bucket_arn
  dag_s3_path          = var.mwaa_config.s3_dags_path
  requirements_s3_path = "requirements.txt"
  plugins_s3_path      = "plugins.zip"
  airflow_version      = "2.8.1"
  kms_key              = aws_kms_key.mwaa_kms.arn

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
    "core.lazy_load_plugins" = "False"
    "webserver.expose_config" = "True"
    "core.default_task_retries" = "3"
    "core.parallelism" = "40"
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
# IAM Role for Airflow UI Access (FIXED - Custom policy)
#########################
resource "aws_iam_role" "mwaa_ui_access" {
  name = "${var.mwaa_config.mwaa_name}-ui-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, { Name = "${var.mwaa_config.mwaa_name}-ui-access-role" })
}

# Custom policy for UI access (replaces non-existent managed policy)
resource "aws_iam_role_policy" "mwaa_ui_access" {
  name = "${var.mwaa_config.mwaa_name}-ui-access-policy"
  role = aws_iam_role.mwaa_ui_access.id

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
