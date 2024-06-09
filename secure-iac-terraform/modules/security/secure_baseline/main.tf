/**
 * # AWS Security Baseline Module
 * This module implements security best practices for AWS environments
 * following CIS AWS Foundations Benchmark recommendations.
 */

provider "aws" {
  region = var.region
}

# Create KMS key for encryption
resource "aws_kms_key" "main" {
  description             = "KMS key for ${var.environment} environment"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_policy.json
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-kms-key"
    }
  )
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.environment}-key"
  target_key_id = aws_kms_key.main.key_id
}

data "aws_iam_policy_document" "kms_policy" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

data "aws_caller_identity" "current" {}

# CloudTrail with encrypted logs
resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.main.arn
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-cloudtrail"
    }
  )
}

# S3 bucket for CloudTrail logs with secure configuration
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.environment}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = var.force_destroy_buckets
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-cloudtrail-logs"
    }
  )
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  
  rule {
    id     = "log-expiration"
    status = "Enabled"
    
    expiration {
      days = var.log_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }
  
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

# GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
  
  finding_publishing_frequency = "SIX_HOURS"
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-guardduty"
    }
  )
}

# AWS Config
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.environment}-config-recorder"
  role_arn = aws_iam_role.config_role.arn
  
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.environment}-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config.id
  s3_key_prefix  = "config"
  sns_topic_arn  = var.enable_config_notifications ? aws_sns_topic.config[0].arn : null
  
  snapshot_delivery_properties {
    delivery_frequency = "Six_Hours"
  }
  
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  
  depends_on = [aws_config_delivery_channel.main]
}

# S3 bucket for AWS Config with secure configuration
resource "aws_s3_bucket" "config" {
  bucket = "${var.environment}-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = var.force_destroy_buckets
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-config"
    }
  )
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  
  rule {
    id     = "config-expiration"
    status = "Enabled"
    
    expiration {
      days = var.log_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket_policy.json
}

data "aws_iam_policy_document" "config_bucket_policy" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
  }
  
  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

# IAM role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "${var.environment}-config-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
  
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# SNS topic for Config notifications
resource "aws_sns_topic" "config" {
  count  = var.enable_config_notifications ? 1 : 0
  name   = "${var.environment}-config-notifications"
  kms_master_key_id = aws_kms_key.main.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-config-notifications"
    }
  )
}

# Security Hub
resource "aws_securityhub_account" "main" {
  count = var.enable_security_hub ? 1 : 0
}

resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/1.2.0"
  
  depends_on = [aws_securityhub_account.main]
}

# Password policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}
