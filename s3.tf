module "s3" {
  source = "git::https://github.com/361-by-finca/aws-s3-terraform-module.git"

  for_each = var.s3_config

  bucket_name      = each.value.bucket_name
  force_destroy    = each.value.force_destroy
  enable_lifecycle = each.value.enable_lifecycle
  lifecycle_config = each.value.lifecycle_config

  tags = merge(var.tags, { Name = each.value.bucket_name })
}

locals {
  bucket_folders = flatten([
    for bucket_key, bucket in var.s3_config : [
      for folder in bucket.folders : {
        bucket_key = bucket_key
        bucket     = bucket.bucket_name
        folder     = folder
      }
    ]
  ])
}

resource "aws_s3_object" "folders" {
  for_each = {
    for dir in local.bucket_folders : "${dir.bucket_key}-${dir.folder}" => dir
  }

  bucket  = each.value.bucket
  key     = "${each.value.folder}/"
  content = ""
}

locals {
  s3_map = {
    for bucket_key, bucket_details in module.s3 :
    bucket_key => {
      bucket_id     = bucket_details.s3_bucket_id
      bucket_arn    = bucket_details.s3_bucket_arn
      bucket_domain = bucket_details.s3_bucket_domain_name
    }
  }
}

#########################
# S3 Bucket Encryption Configuration
#########################
resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_encryption" {
  for_each = var.s3_config

  bucket = module.s3[each.key].s3_bucket_id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # This will override existing KMS encryption
    }
  }

  # Force override any existing encryption
  depends_on = [module.s3]
}

#########################
# S3 Bucket Encryption Configuration
#########################
resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_encryption" {
  for_each = var.s3_config

  bucket = module.s3[each.key].s3_bucket_id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # This will override existing KMS encryption
    }
  }

  # Force override any existing encryption
  depends_on = [module.s3]
}

output "s3_buckets" {
  value = local.s3_map
}
