resource "aws_iam_role" "msk_connect_execution" {
  name               = "${var.msk_connect_plugins.connector_name}-execution-role"
  assume_role_policy = data.aws_iam_policy_document.msk_connect_execution_assume_role.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "msk_connect_execution" {
  role   = aws_iam_role.msk_connect_execution.id
  policy = data.aws_iam_policy_document.msk_connect_execution_role_policy.json
}

#################################
# Custom Plugin (Optional)
#################################
resource "aws_mskconnect_custom_plugin" "this" {
  count        = length(var.msk_connect_plugins.folders) > 0 ? 1 : 0
  name         = "${var.msk_connect_plugins.connector_name}-plugin"
  content_type = "ZIP"

  location {
    s3 {
      bucket_arn = module.s3[var.msk_connect_plugins.bucket_name_key].s3_bucket_arn
      file_key   = var.msk_connect_plugins.bucket_name_key
    }
  }

  tags = var.tags
}

#################################
# MSK Connect Connector
#################################
resource "aws_mskconnect_connector" "this" {
  name                       = var.msk_connect_plugins.connector_name
  kafkaconnect_version       = var.msk_connect_plugins.kafkaconnect_version
  service_execution_role_arn = aws_iam_role.msk_connect_execution.arn

  # Which Kafka cluster to connect to
  kafka_cluster {
    apache_kafka_cluster {
      bootstrap_servers = data.aws_msk_cluster.this.bootstrap_brokers
      vpc {
        subnets         = data.aws_subnets.client.ids
        security_groups = [for sg in data.aws_security_group.selected : sg.id]
      }
    }
  }

  # IMPORTANT: client authentication is a top-level block on the connector resource
  # not nested inside apache_kafka_cluster.
  kafka_cluster_client_authentication {
    # NONE | IAM | SASL/SCRAM
    authentication_type = lookup(var.msk_connect_plugins, "authentication_type", "IAM")
    # If using SASL/SCRAM, use the sasl block (example commented)
    # sasl {
    #   username = var.msk_connect_plugins.sasl_username
    #   password {
    #     secret_arn = var.msk_connect_plugins.sasl_password_arn
    #   }
    # }
  }

  # Encryption in transit is also a top-level block.
  kafka_cluster_encryption_in_transit {
    # TLS | PLAINTEXT
    encryption_type = lookup(var.msk_connect_plugins, "encryption_type", "TLS")
  }

  # Capacity: provisioned_capacity or autoscaling (provisioned_capacity shown)
  capacity {
    provisioned_capacity {
      worker_count = var.msk_connect_plugins.connector_worker_count
      # mcu_count = lookup(var.msk_connect_plugins, "mcu_count", 1)  # optional
    }
    # OR, if you prefer autoscaling:
    # autoscaling {
    #   mcu_count       = 1
    #   min_worker_count = 1
    #   max_worker_count = 2
    #   scale_in_policy {
    #     cpu_utilization_percentage = 20
    #   }
    #   scale_out_policy {
    #     cpu_utilization_percentage = 80
    #   }
    # }
  }

  # Optional plugin block (keeps your dynamic plugin approach)
  dynamic "plugin" {
    for_each = length(var.msk_connect_plugins.folders) > 0 ? [1] : []
    content {
      custom_plugin {
        arn      = aws_mskconnect_custom_plugin.this[0].arn
        revision = aws_mskconnect_custom_plugin.this[0].latest_revision
      }
    }
  }

  connector_configuration = merge(
    {
      "connector.class" = var.msk_connect_plugins.connector_class
      "tasks.max"       = var.msk_connect_plugins.connector_tasks_max
      "topics"          = var.msk_connect_plugins.connector_topics
      "s3.bucket.name"  = var.msk_connect_plugins.bucket_name
      "s3.region"       = var.msk_connect_plugins.s3_region
      "flush.size"      = var.msk_connect_plugins.flush_size
      "format.class"    = var.msk_connect_plugins.format_class
      "key.converter"   = var.msk_connect_plugins.key_converter
      "value.converter" = var.msk_connect_plugins.value_converter
    },
    var.msk_connect_plugins.connector_config
  )

  tags = var.tags
}
