package compliance.aws.iam

# CIS AWS 1.1: Avoid the use of the "root" account
deny[msg] {
  input.resource_type == "aws_iam_user"
  user := input.resource.aws_iam_user[_]
  user.name == "root"
  
  msg := "CIS 1.1 Violation: IAM root user should not be used for day-to-day operations"
}

# CIS AWS 1.2: Ensure multi-factor authentication (MFA) is enabled for all IAM users with console access
deny[msg] {
  input.resource_type == "aws_iam_user"
  user := input.resource.aws_iam_user[_]
  
  # Check if user has console access
  has_console_access(user)
  
  # Check if MFA is not enabled
  not has_mfa_enabled(user)
  
  msg := sprintf("CIS 1.2 Violation: IAM user '%v' with console access does not have MFA enabled", [user.name])
}

# CIS AWS 1.3: Ensure credentials unused for 90 days or greater are disabled
warn[msg] {
  input.resource_type == "aws_iam_user"
  user := input.resource.aws_iam_user[_]
  
  # This would need to be checked via AWS API in real implementation
  # For this example, we'll use a tag to simulate last usage
  user.tags.last_used_days_ago > 90
  
  msg := sprintf("CIS 1.3 Violation: IAM user '%v' has credentials unused for more than 90 days", [user.name])
}

# CIS AWS 1.4: Ensure access keys are rotated every 90 days or less
deny[msg] {
  input.resource_type == "aws_iam_access_key"
  key := input.resource.aws_iam_access_key[_]
  
  # This would need to be checked via AWS API in real implementation
  # For this example, we'll use a tag to simulate key age
  key.tags.age_in_days > 90
  
  msg := sprintf("CIS 1.4 Violation: Access key '%v' for user '%v' has not been rotated in the last 90 days", [key.id, key.user])
}

# CIS AWS 1.5: Ensure IAM password policy requires at least one uppercase letter
deny[msg] {
  input.resource_type == "aws_iam_account_password_policy"
  policy := input.resource.aws_iam_account_password_policy[_]
  
  not policy.require_uppercase_characters
  
  msg := "CIS 1.5 Violation: IAM password policy does not require at least one uppercase letter"
}

# CIS AWS 1.6: Ensure IAM password policy requires at least one lowercase letter
deny[msg] {
  input.resource_type == "aws_iam_account_password_policy"
  policy := input.resource.aws_iam_account_password_policy[_]
  
  not policy.require_lowercase_characters
  
  msg := "CIS 1.6 Violation: IAM password policy does not require at least one lowercase letter"
}

# CIS AWS 1.7: Ensure IAM password policy requires at least one symbol
deny[msg] {
  input.resource_type == "aws_iam_account_password_policy"
  policy := input.resource.aws_iam_account_password_policy[_]
  
  not policy.require_symbols
  
  msg := "CIS 1.7 Violation: IAM password policy does not require at least one symbol"
}

# CIS AWS 1.8: Ensure IAM password policy requires at least one number
deny[msg] {
  input.resource_type == "aws_iam_account_password_policy"
  policy := input.resource.aws_iam_account_password_policy[_]
  
  not policy.require_numbers
  
  msg := "CIS 1.8 Violation: IAM password policy does not require at least one number"
}

# CIS AWS 1.9: Ensure IAM password policy requires minimum length of 14 or greater
deny[msg] {
  input.resource_type == "aws_iam_account_password_policy"
  policy := input.resource.aws_iam_account_password_policy[_]
  
  policy.minimum_password_length < 14
  
  msg := sprintf("CIS 1.9 Violation: IAM password policy requires minimum length of %v, but should be at least 14", [policy.minimum_password_length])
}

# CIS AWS 1.10: Ensure IAM password policy prevents password reuse
deny[msg] {
  input.resource_type == "aws_iam_account_password_policy"
  policy := input.resource.aws_iam_account_password_policy[_]
  
  policy.password_reuse_prevention < 24
  
  msg := sprintf("CIS 1.10 Violation: IAM password policy allows reuse after %v passwords, but should be at least 24", [policy.password_reuse_prevention])
}

# CIS AWS 1.11: Ensure IAM password policy expires passwords within 90 days or less
deny[msg] {
  input.resource_type == "aws_iam_account_password_policy"
  policy := input.resource.aws_iam_account_password_policy[_]
  
  policy.max_password_age > 90
  
  msg := sprintf("CIS 1.11 Violation: IAM password policy allows passwords to be used for %v days, but should be 90 days or less", [policy.max_password_age])
}

# CIS AWS 1.12: Ensure no root account access key exists
deny[msg] {
  input.resource_type == "aws_iam_access_key"
  key := input.resource.aws_iam_access_key[_]
  
  key.user == "root"
  
  msg := "CIS 1.12 Violation: Root account has an access key"
}

# CIS AWS 1.13: Ensure MFA is enabled for the "root" account
deny[msg] {
  input.account_info.root_account
  
  not input.account_info.root_account.mfa_enabled
  
  msg := "CIS 1.13 Violation: MFA is not enabled for the root account"
}

# CIS AWS 1.14: Ensure hardware MFA is enabled for the "root" account
warn[msg] {
  input.account_info.root_account
  
  input.account_info.root_account.mfa_enabled
  not input.account_info.root_account.hardware_mfa_enabled
  
  msg := "CIS 1.14 Violation: Hardware MFA is not enabled for the root account"
}

# CIS AWS 1.15: Ensure security questions are registered in the AWS account
warn[msg] {
  input.account_info
  
  not input.account_info.security_questions_registered
  
  msg := "CIS 1.15 Violation: Security questions are not registered for the AWS account"
}

# CIS AWS 1.16: Ensure IAM policies are attached only to groups or roles
deny[msg] {
  input.resource_type == "aws_iam_user_policy"
  policy := input.resource.aws_iam_user_policy[_]
  
  msg := sprintf("CIS 1.16 Violation: IAM policy '%v' is attached directly to user '%v' instead of a group or role", [policy.name, policy.user])
}

deny[msg] {
  input.resource_type == "aws_iam_user_policy_attachment"
  attachment := input.resource.aws_iam_user_policy_attachment[_]
  
  msg := sprintf("CIS 1.16 Violation: IAM policy '%v' is attached directly to user '%v' instead of a group or role", [attachment.policy_arn, attachment.user])
}

# Helper functions
has_console_access(user) {
  # In a real implementation, this would check if the user has console access
  # For this example, we'll assume all users have console access unless specified otherwise
  not user.tags.console_access == "false"
}

has_mfa_enabled(user) {
  # In a real implementation, this would check if the user has MFA enabled via AWS API
  # For this example, we'll use a tag to simulate MFA status
  user.tags.mfa_enabled == "true"
}
