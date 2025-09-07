#########################
# AWS Data Sources
#########################
data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

#########################
# MWAA IAM Assume Role
#########################
data "aws_iam_policy_document" "mwaa_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = [
        "airflow.amazonaws.com",
        "airflow-env.amazonaws.com",
        "batch.amazonaws.com",
        "ssm.amazonaws.com",
        "lambda.amazonaws.com",
        "s3.amazonaws.com"
      ]
    }

    dynamic "principals" {
      for_each = var.mwaa_config.additional_principal_arns
      content {
        type        = "AWS"
        identifiers = [each.value]
      }
    }
  }
}

#########################
# MWAA IAM Policy
#########################
data "aws_iam_policy_document" "mwaa" {
  # Airflow environment access
  statement {
    effect = "Allow"
    actions = [
      "airflow:PublishMetrics",
      "airflow:CreateWebLoginToken"
    ]
    resources = [
      "arn:${data.aws_partition.current.id}:airflow:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:environment/${var.mwaa_config.mwaa_name}"
    ]
  }

  # S3 bucket access
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject*",
      "s3:GetBucket*",
      "s3:List*"
    ]
    resources = [
      local.source_bucket_arn,
      "${local.source_bucket_arn}/*"
    ]
  }

  # CloudWatch Logs
  statement {
    effect  = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:CreateLogGroup",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:GetLogRecord",
      "logs:GetLogGroupFields",
      "logs:GetQueryResults"
    ]
    resources = [
      "arn:${data.aws_partition.current.id}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:airflow-${var.mwaa_config.mwaa_name}-*"
    ]
  }

  statement {
    effect  = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "cloudwatch:PutMetricData",
      "s3:GetAccountPublicAccessBlock",
      "eks:DescribeCluster"
    ]
    resources = ["*"]
  }

  # SQS access
  statement {
    effect  = "Allow"
    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage",
      "sqs:SendMessage"
    ]
    resources = [
      "arn:${data.aws_partition.current.id}:sqs:${data.aws_region.current.id}:*:airflow-celery-*"
    ]
  }

  # AWS Batch access
  statement {
    effect  = "Allow"
    actions = ["batch:*"]
    resources = [
      "arn:${data.aws_partition.current.id}:batch:*:${data.aws_caller_identity.current.account_id}:*"
    ]
  }

  # SSM access
  statement {
    effect  = "Allow"
    actions = ["ssm:*"]
    resources = [
      "arn:${data.aws_partition.current.id}:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter/*"
    ]
  }

  # Lambda Logs access
  statement {
    effect  = "Allow"
    actions = ["logs:*"]
    resources = [
      "arn:${data.aws_partition.current.id}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
    ]
  }

  # CloudWatch access
  statement {
    effect  = "Allow"
    actions = ["cloudwatch:*"]
    resources = [
      "arn:${data.aws_partition.current.id}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
    ]
  }
}

data "aws_vpc" "this" {
  filter {
    name   = "tag:Name"
    values = [var.msk_connect_plugins.vpc_name]
  }
}

data "aws_subnets" "client" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.this.id]
  }

  filter {
    name   = "tag:Name"
    values = var.msk_connect_plugins.msk_subnet_names
  }
}

data "aws_security_group" "selected" {
  for_each = toset(var.msk_connect_plugins.msk_security_group_names)

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.this.id]
  }

  filter {
    name   = "group-name"
    values = [each.value]
  }
}

data "aws_msk_cluster" "this" {
  cluster_name = var.msk_connect_plugins.msk_cluster_name
}

data "aws_iam_policy_document" "msk_connect_execution_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["kafkaconnect.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "msk_connect_execution_role_policy" {
  statement {
    sid    = "AllowConnectToMSKCluster"
    effect = "Allow"
    actions = [
      "kafka-cluster:Connect",
      "kafka-cluster:AlterCluster",
      "kafka-cluster:DescribeCluster",
      "kafka-cluster:CreateTopic",
      "kafka-cluster:WriteData",
      "kafka-cluster:ReadData",
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:AlterGroup",
      "kafka-cluster:DescribeGroup"
    ]
    resources = [
      data.aws_msk_cluster.this.arn,
      "${data.aws_msk_cluster.this.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ]
    resources = [module.s3[var.msk_connect_plugins.bucket_name_key].s3_bucket_arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject"
    ]
    resources = ["${module.s3[var.msk_connect_plugins.bucket_name_key].s3_bucket_arn}/*"]
  }
}
