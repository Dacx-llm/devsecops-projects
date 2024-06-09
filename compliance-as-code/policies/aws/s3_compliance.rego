package compliance.aws.s3

# CIS AWS 2.1.5: Ensure S3 buckets are configured with 'Block public access'
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  bucket := input.resource.aws_s3_bucket[_]
  not input.resource.aws_s3_bucket_public_access_block
  
  msg := sprintf("S3 bucket '%v' does not have public access blocks configured", [bucket.id])
}

# CIS AWS 2.1.1: Ensure all S3 buckets employ encryption-at-rest
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  bucket := input.resource.aws_s3_bucket[_]
  not bucket.server_side_encryption_configuration
  
  msg := sprintf("S3 bucket '%v' is not configured with default encryption", [bucket.id])
}

# CIS AWS 2.1.2: Ensure S3 Bucket Policy allows HTTPS requests only
deny[msg] {
  input.resource_type == "aws_s3_bucket_policy"
  policy := input.resource.aws_s3_bucket_policy[_]
  
  not contains(policy.policy, "aws:SecureTransport")
  
  msg := sprintf("S3 bucket policy '%v' does not enforce HTTPS-only access", [policy.id])
}

# CIS AWS 2.1.3: Ensure MFA Delete is enabled on S3 buckets
warn[msg] {
  input.resource_type == "aws_s3_bucket"
  bucket := input.resource.aws_s3_bucket[_]
  
  not bucket.versioning[_].mfa_delete
  
  msg := sprintf("S3 bucket '%v' does not have MFA Delete enabled", [bucket.id])
}

# Helper function to check if a string contains a substring
contains(str, substr) {
  contains(str, substr)
}

# PCI DSS 3.2.1: Ensure S3 buckets storing cardholder data are properly secured
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  bucket := input.resource.aws_s3_bucket[_]
  
  # Check if bucket name or tags indicate it stores PCI data
  pci_data_bucket(bucket)
  
  # Check for required security controls
  not bucket.server_side_encryption_configuration
  
  msg := sprintf("PCI-DSS violation: S3 bucket '%v' containing cardholder data must be encrypted", [bucket.id])
}

# Helper function to identify buckets that might contain PCI data
pci_data_bucket(bucket) {
  contains(bucket.id, "pci")
}

pci_data_bucket(bucket) {
  contains(bucket.id, "payment")
}

pci_data_bucket(bucket) {
  contains(bucket.id, "card")
}

pci_data_bucket(bucket) {
  bucket.tags.data_classification == "pci"
}

# GDPR: Ensure S3 buckets storing personal data are properly secured
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  bucket := input.resource.aws_s3_bucket[_]
  
  # Check if bucket name or tags indicate it stores personal data
  personal_data_bucket(bucket)
  
  # Check for required security controls
  not bucket.server_side_encryption_configuration
  
  msg := sprintf("GDPR violation: S3 bucket '%v' containing personal data must be encrypted", [bucket.id])
}

# Helper function to identify buckets that might contain personal data
personal_data_bucket(bucket) {
  contains(bucket.id, "personal")
}

personal_data_bucket(bucket) {
  contains(bucket.id, "customer")
}

personal_data_bucket(bucket) {
  bucket.tags.data_classification == "personal"
}

personal_data_bucket(bucket) {
  bucket.tags.gdpr == "in-scope"
}
