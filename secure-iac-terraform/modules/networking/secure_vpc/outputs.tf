output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.secure_vpc.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.secure_vpc.cidr_block
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "database_subnet_ids" {
  description = "List of database subnet IDs"
  value       = aws_subnet.database[*].id
}

output "private_route_table_id" {
  description = "ID of the private route table"
  value       = aws_route_table.private.id
}

output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}

output "database_route_table_id" {
  description = "ID of the database route table"
  value       = aws_route_table.database.id
}

output "nat_gateway_id" {
  description = "ID of the NAT Gateway (if enabled)"
  value       = var.enable_nat_gateway ? aws_nat_gateway.nat[0].id : null
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.igw.id
}

output "vpc_endpoint_s3_id" {
  description = "ID of the S3 VPC Endpoint"
  value       = aws_vpc_endpoint.s3.id
}

output "vpc_endpoint_ssm_id" {
  description = "ID of the SSM VPC Endpoint (if enabled)"
  value       = var.enable_ssm_endpoint ? aws_vpc_endpoint.ssm[0].id : null
}

output "vpc_flow_log_id" {
  description = "ID of the VPC Flow Log"
  value       = aws_flow_log.vpc_flow_log.id
}

output "vpc_endpoints_security_group_id" {
  description = "ID of the security group for VPC endpoints"
  value       = aws_security_group.vpc_endpoints.id
}
