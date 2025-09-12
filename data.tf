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
      type = "Service"
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
    effect = "Allow"
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
    effect = "Allow"
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
    effect = "Allow"
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
