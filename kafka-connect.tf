#############################################
# IAM Role + Policy (if enabled)
#############################################
resource "aws_iam_role" "connect_execution" {
  count = var.connect_config.create_iam_role ? 1 : 0

  name = "${var.connect_config.name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "kafkaconnect.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_policy" "connect_policy" {
  count  = var.connect_config.create_iam_role ? 1 : 0
  name   = "${var.connect_config.name}-policy"
  policy = data.aws_iam_policy_document.connect_execution.json
}

resource "aws_iam_role_policy_attachment" "connect_execution_attach" {
  count      = var.connect_config.create_iam_role ? 1 : 0
  role       = aws_iam_role.connect_execution[0].name
  policy_arn = aws_iam_policy.connect_policy[0].arn
}

#############################################
# CloudWatch Log Group
#############################################
resource "aws_cloudwatch_log_group" "mskconnect" {
  name              = "/aws/mskconnect/${var.connect_config.name}"
  retention_in_days = 14
  tags              = var.tags
}

#############################################
# Custom Plugins
#############################################
resource "aws_mskconnect_custom_plugin" "s3_plugin" {
  for_each     = { for p in var.connect_config.connect_plugins : p.name => p }
  name         = "${var.connect_config.name}-${each.key}"
  content_type = "ZIP"

  location {
    s3 {
      bucket_arn = "arn:aws:s3:::${var.s3_config[each.value.bucket_key].bucket_name}"
      file_key   = each.value.file_key
    }
  }

  tags = var.tags
}

#############################################
# Connector Configuration
#############################################
locals {
  connector_configuration = {
    "connector.class"           = "io.confluent.connect.s3.S3SinkConnector"
    "s3.region"                 = data.aws_region.current.id
    "flush.size"                = "1"
    "schema.compatibility"      = "NONE"
    "tasks.max"                 = "1"
    "topics"                    = var.connect_config.topic_config.topic_name
    "timezone"                  = "UTC"
    "rotate.interval.ms"        = "600000"
    "format.class"              = "io.confluent.connect.s3.format.json.JsonFormat"
    "partitioner.class"         = "io.confluent.connect.storage.partitioner.DefaultPartitioner"
    "storage.class"             = "io.confluent.connect.s3.storage.S3Storage"
    "s3.bucket.name"            = var.s3_config[var.connect_config.s3_bucket_key].bucket_name
    "path.format"               = "year=!{timestamp:YYYY}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}"
    "key.converter"             = "org.apache.kafka.connect.storage.StringConverter"
    "value.converter"           = "org.apache.kafka.connect.storage.StringConverter"
    "offset.storage.partitions" = "1"
    "status.storage.partitions" = "1"
    "config.storage.partitions" = "1"
  }
}

#############################################
# MSK Connect Connector
#############################################
resource "aws_mskconnect_connector" "this" {
  depends_on = [aws_cloudwatch_log_group.mskconnect]

  name                 = var.connect_config.name
  kafkaconnect_version = var.connect_config.kafkaconnect_version

  capacity {
    provisioned_capacity {
      mcu_count    = var.connect_config.scaling.mcu_count
      worker_count = var.connect_config.scaling.worker_count
    }
  }

  connector_configuration = local.connector_configuration

  kafka_cluster {
    apache_kafka_cluster {
      bootstrap_servers = data.aws_msk_bootstrap_brokers.selected.bootstrap_brokers_sasl_scram

      vpc {
        security_groups = var.connect_config.security_groups
        subnets         = var.connect_config.subnet_ids
      }
    }
  }

  kafka_cluster_client_authentication {
    authentication_type = "NONE"
  }

  kafka_cluster_encryption_in_transit {
    encryption_type = "TLS"
  }

  log_delivery {
    worker_log_delivery {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.mskconnect.name
      }
    }
  }

  dynamic "plugin" {
    for_each = aws_mskconnect_custom_plugin.s3_plugin
    content {
      custom_plugin {
        arn      = plugin.value.arn
        revision = plugin.value.latest_revision
      }
    }
  }

  service_execution_role_arn = var.connect_config.create_iam_role ? aws_iam_role.connect_execution[0].arn : null
  tags                       = var.tags
}

#############################################
# Associate SCRAM secret with MSK cluster
#############################################
resource "aws_msk_scram_secret_association" "this" {
  cluster_arn     = data.aws_msk_cluster.selected.arn
  secret_arn_list = [data.aws_secretsmanager_secret_version.msk_connect_secret.arn]

  depends_on = [aws_mskconnect_connector.this]
}

#############################################
# VPC Endpoint for S3
#############################################
resource "aws_vpc_endpoint" "s3_gateway" {
  vpc_id            = var.connect_config.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.id}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = var.connect_config.route_table_ids

  tags = merge(
    var.tags,
    { Name = "${var.connect_config.name}-s3-endpoint" }
  )
}
