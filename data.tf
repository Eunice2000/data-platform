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
############################################################
# Data sources for existing MSK cluster and SCRAM secret
###########################################################

#############################################
# Fetch the existing MSK cluster
#############################################
data "aws_msk_cluster" "selected" {
  cluster_name = var.connect_config.kafka_cluster_name
}

#############################################
# Fetch the MSK SCRAM secret from Secrets Manager
#############################################
data "aws_secretsmanager_secret" "msk_connect_secret" {
  name = "AmazonMSK_microservice-cluster-new"  # match the actual secret
}

data "aws_secretsmanager_secret_version" "msk_connect_secret" {
  secret_id = data.aws_secretsmanager_secret.msk_connect_secret.id
}

#############################################
# Policy JSON for MSK Connect execution role
#############################################
data "aws_iam_policy_document" "connect_execution" {
  statement {
    sid     = "AllowMSKCluster"
    effect  = "Allow"
    actions = ["kafka-cluster:Connect", "kafka-cluster:DescribeCluster"]
    resources = [
      "arn:aws:kafka:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:cluster/*"
    ]
  }

  statement {
    sid     = "AllowTopicAccess"
    effect  = "Allow"
    actions = ["kafka-cluster:CreateTopic", "kafka-cluster:WriteData", "kafka-cluster:ReadData", "kafka-cluster:DescribeTopic"]
    resources = [
      "arn:aws:kafka:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:topic/*"
    ]
  }

  statement {
    sid     = "AllowGroupAccess"
    effect  = "Allow"
    actions = ["kafka-cluster:AlterGroup", "kafka-cluster:DescribeGroup"]
    resources = [
      "arn:aws:kafka:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:group/*"
    ]
  }

  statement {
    sid     = "AllowCloudWatchLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }

  # Dynamic statements for S3 access
  dynamic "statement" {
    for_each = var.connect_config.s3_access
    content {
      sid     = "AllowS3Access${replace(statement.value.bucket_key, "/[^0-9A-Za-z]/", "")}" # sanitized alphanumeric only
      effect  = "Allow"
      actions = statement.value.actions
      resources = [
        "arn:aws:s3:::${var.s3_config[statement.value.bucket_key].bucket_name}",
        "arn:aws:s3:::${var.s3_config[statement.value.bucket_key].bucket_name}/*"
      ]
    }
  }
}
