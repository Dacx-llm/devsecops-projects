/**
 * # Secure VPC Module
 * This module creates a secure VPC configuration with proper network segmentation,
 * flow logs, and security controls.
 */

provider "aws" {
  region = var.region
}

resource "aws_vpc" "secure_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-secure-vpc"
    }
  )
}

# Create private subnets for internal resources
resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = var.availability_zones[count.index % length(var.availability_zones)]
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-private-${count.index + 1}"
      Tier = "private"
    }
  )
}

# Create public subnets for load balancers and bastion hosts
resource "aws_subnet" "public" {
  count             = length(var.public_subnets)
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = var.public_subnets[count.index]
  availability_zone = var.availability_zones[count.index % length(var.availability_zones)]
  map_public_ip_on_launch = false # Disable auto-assign public IPs for security
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-public-${count.index + 1}"
      Tier = "public"
    }
  )
}

# Create a dedicated subnet for database instances
resource "aws_subnet" "database" {
  count             = length(var.database_subnets)
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = var.database_subnets[count.index]
  availability_zone = var.availability_zones[count.index % length(var.availability_zones)]
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-database-${count.index + 1}"
      Tier = "database"
    }
  )
}

# Internet Gateway for public subnets
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.secure_vpc.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-igw"
    }
  )
}

# NAT Gateway with Elastic IP for private subnet internet access
resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? 1 : 0
  domain = "vpc"
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-nat-eip"
    }
  )
}

resource "aws_nat_gateway" "nat" {
  count         = var.enable_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-nat-gw"
    }
  )
  
  depends_on = [aws_internet_gateway.igw]
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.secure_vpc.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-public-rt"
    }
  )
}

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.secure_vpc.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-private-rt"
    }
  )
}

resource "aws_route" "private_nat_gateway" {
  count                  = var.enable_nat_gateway ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat[0].id
}

resource "aws_route_table" "database" {
  vpc_id = aws_vpc.secure_vpc.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-database-rt"
    }
  )
}

# Route table associations
resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "database" {
  count          = length(var.database_subnets)
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# VPC Flow Logs for network monitoring and security analysis
resource "aws_flow_log" "vpc_flow_log" {
  log_destination      = aws_cloudwatch_log_group.flow_log.arn
  log_destination_type = "cloud-watch-logs"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.secure_vpc.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-vpc-flow-logs"
    }
  )
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/aws/vpc-flow-log/${var.environment}"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-vpc-flow-log-group"
    }
  )
}

resource "aws_iam_role" "vpc_flow_log_role" {
  name = "${var.environment}-vpc-flow-log-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
  
  tags = var.tags
}

resource "aws_iam_role_policy" "vpc_flow_log_policy" {
  name = "${var.environment}-vpc-flow-log-policy"
  role = aws_iam_role.vpc_flow_log_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "${aws_cloudwatch_log_group.flow_log.arn}:*"
      }
    ]
  })
}

# Network ACLs for additional security layer
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.secure_vpc.id
  subnet_ids = aws_subnet.public[*].id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-public-nacl"
    }
  )
}

resource "aws_network_acl_rule" "public_ingress" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "public_egress" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.secure_vpc.id
  subnet_ids = aws_subnet.private[*].id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-private-nacl"
    }
  )
}

resource "aws_network_acl_rule" "private_ingress" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = aws_vpc.secure_vpc.cidr_block
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl_rule" "private_egress" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

# VPC Endpoints for secure access to AWS services without internet
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.secure_vpc.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id, aws_route_table.database.id]
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-s3-endpoint"
    }
  )
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.environment}-vpc-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.secure_vpc.id
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.secure_vpc.cidr_block]
    description = "Allow HTTPS from VPC CIDR"
  }
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-vpc-endpoints-sg"
    }
  )
}

resource "aws_vpc_endpoint" "ssm" {
  count               = var.enable_ssm_endpoint ? 1 : 0
  vpc_id              = aws_vpc.secure_vpc.id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-ssm-endpoint"
    }
  )
}

# Default security group with no ingress/egress
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.secure_vpc.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-default-sg"
    }
  )
}
