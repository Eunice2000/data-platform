#########################
# S3 Bucket for DAGs, Plugins, and Requirements
#########################
resource "aws_s3_bucket" "mwaa_dags" {
  bucket = "${var.mwaa_config.mwaa_name}-dags-bucket"
  
  tags = merge(var.tags, { 
    Name = "${var.mwaa_config.mwaa_name}-dags-bucket",
    Purpose = "MWAA DAGs and dependencies"
  })
}

resource "aws_s3_bucket_versioning" "mwaa_dags" {
  bucket = aws_s3_bucket.mwaa_dags.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "mwaa_dags" {
  bucket = aws_s3_bucket.mwaa_dags.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

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
# MWAA Execution Role Policy
#########################
resource "aws_iam_role_policy" "mwaa_execution_policy" {
  name = "${var.mwaa_config.mwaa_name}-execution-policy"
  role = aws_iam_role.mwaa_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
      {
        Effect = "Allow"
        Action = "iam:CreatePolicy"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/service-role/MWAA-Execution-Policy*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:AttachRolePolicy",
          "iam:CreateRole"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/service-role/AmazonMWAA*"
      },
      {
        Effect = "Allow"
        Action = "iam:CreateServiceLinkedRole"
        Resource = "arn:aws:iam::*:role/aws-service-role/airflow.amazonaws.com/AWSServiceRoleForAmazonMWAA"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:ListAllMyBuckets",
          "s3:ListBucket",
          "s3:ListBucketVersions"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:PutObject",
          "s3:GetEncryptionConfiguration"
        ]
        Resource = "arn:aws:s3:::*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeRouteTables"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup"
        ]
        Resource = "arn:aws:ec2:*:*:security-group/airflow-security-group-*"
      },
      {
        Effect = "Allow"
        Action = "kms:ListAliases"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "ec2:CreateVpcEndpoint"
        Resource = [
          "arn:aws:ec2:*:*:vpc-endpoint/*",
          "arn:aws:ec2:*:*:vpc/*",
          "arn:aws:ec2:*:*:subnet/*",
          "arn:aws:ec2:*:*:security-group/*"
        ]
      },
      {
        Effect = "Allow"
        Action = "ec2:CreateNetworkInterface"
        Resource = [
          "arn:aws:ec2:*:*:subnet/*",
          "arn:aws:ec2:*:*:network-interface/*"
        ]
      },
      # Additional permissions for MWAA operations
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject*",
          "s3:PutObject*",
          "s3:DeleteObject*"
        ]
        Resource = [
          "${aws_s3_bucket.mwaa_dags.arn}/*",
          "${aws_s3_bucket.mwaa_dags.arn}"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:GetLogEvents",
          "logs:GetLogRecord",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:*:*:log-group:airflow-${var.mwaa_config.mwaa_name}-*"
      },
      {
        Effect = "Allow"
        Action = "cloudwatch:PutMetricData"
        Resource = "*"
      },
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
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.mwaa_kms.arn
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

  # Self-referencing inbound rules
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  # Allow HTTPS for web server
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_config.cidr]
  }

  # Allow PostgreSQL for metadata database
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_config.cidr]
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
# VPC Endpoints
#########################
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = module.vpc.private_route_table_ids

  tags = merge(var.tags, { Name = "${var.vpc_config.name}-s3-endpoint" })
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = module.vpc.vpc_id
  service_name        = "com.amazonaws.${var.region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = slice(module.vpc.private_subnets, 0, 2)
  security_group_ids  = [aws_security_group.mwaa_sg.id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.vpc_config.name}-kms-endpoint" })
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = module.vpc.vpc_id
  service_name        = "com.amazonaws.${var.region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = slice(module.vpc.private_subnets, 0, 2)
  security_group_ids  = [aws_security_group.mwaa_sg.id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.vpc_config.name}-logs-endpoint" })
}

resource "aws_vpc_endpoint" "sqs" {
  vpc_id              = module.vpc.vpc_id
  service_name        = "com.amazonaws.${var.region}.sqs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = slice(module.vpc.private_subnets, 0, 2)
  security_group_ids  = [aws_security_group.mwaa_sg.id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.vpc_config.name}-sqs-endpoint" })
}

#########################
# MWAA Environment
#########################
resource "aws_mwaa_environment" "mwaa" {
  name               = var.mwaa_config.mwaa_name
  execution_role_arn = aws_iam_role.mwaa_execution_role.arn
  source_bucket_arn  = aws_s3_bucket.mwaa_dags.arn
  dag_s3_path        = "dags/"
  requirements_s3_path = "requirements.txt"
  plugins_s3_path    = "plugins.zip"
  airflow_version    = "2.8.1"  # Latest tested version per requirements
  kms_key            = aws_kms_key.mwaa_kms.arn

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
    "core.lazy_load_plugins" = "False"  # Required for custom plugins in Airflow v2 :cite[1]
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
    aws_vpc_endpoint.s3,
    aws_vpc_endpoint.kms,
    aws_vpc_endpoint.logs,
    aws_vpc_endpoint.sqs
  ]
}

#########################
# IAM Role for Airflow UI Access
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

resource "aws_iam_role_policy_attachment" "mwaa_ui_access" {
  role       = aws_iam_role.mwaa_ui_access.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonMWAAWebServerAccess"
}
