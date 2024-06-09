# Secure Infrastructure as Code (IaC) with Terraform

This project demonstrates secure Infrastructure as Code (IaC) practices using Terraform, with integrated security scanning, compliance checks, and automated remediation.

## Features

- Secure Terraform modules for AWS, Azure, and GCP
- Automated IaC security scanning with Checkov, TFSec, and Terrascan
- Compliance as Code with Open Policy Agent (OPA)
- Secret management integration with HashiCorp Vault
- Drift detection and automated remediation
- Security-focused CI/CD pipeline for infrastructure deployment
- Least privilege IAM configurations

## Architecture

The project implements a secure-by-default approach to infrastructure provisioning:

1. **Secure Base Modules**
   - Hardened VPC/VNET configurations
   - Security group rules with least privilege
   - Encrypted storage by default
   - Private networking with proper segmentation

2. **Security Controls**
   - WAF and DDoS protection
   - Logging and monitoring
   - Network security with NACLs and security groups
   - Key management with KMS/Key Vault

3. **Compliance Frameworks**
   - CIS Benchmark compliance
   - NIST 800-53 controls
   - SOC2 requirements
   - GDPR/CCPA considerations

## Getting Started

### Prerequisites

- Terraform >= 1.0.0
- AWS CLI, Azure CLI, or GCP CLI (depending on your cloud provider)
- HashiCorp Vault
- Git

### Installation

1. Clone this repository
2. Set up Vault for secret management
3. Configure your cloud provider credentials
4. Initialize Terraform

```bash
terraform init
terraform plan -out=tfplan
# Run security scan on the plan
checkov -f tfplan
# If no critical issues, apply
terraform apply tfplan
```

## Security Tools Integrated

- **Static Analysis**
  - Checkov
  - TFSec
  - Terrascan
  - Snyk IaC

- **Policy Enforcement**
  - Open Policy Agent (OPA)
  - Sentinel (HashiCorp Enterprise)
  - Cloud provider policy frameworks (AWS Config, Azure Policy)

- **Secret Management**
  - HashiCorp Vault
  - Cloud KMS/Key Management

- **Compliance**
  - InSpec
  - Compliance as Code policies

## Project Structure

```
.
├── modules/                  # Reusable secure infrastructure modules
│   ├── networking/           # Secure VPC/VNET configurations
│   ├── compute/              # Hardened compute resources
│   ├── database/             # Secure database configurations
│   └── security/             # Security-specific resources
├── environments/             # Environment-specific configurations
│   ├── dev/
│   ├── staging/
│   └── prod/
├── policies/                 # OPA and compliance policies
├── scripts/                  # Helper scripts for security checks
└── .github/workflows/        # CI/CD pipeline configuration
```

## Best Practices Implemented

- All resources are created with secure defaults
- Infrastructure is immutable and version-controlled
- Secrets are never stored in code
- All changes go through security scanning
- Least privilege principle is applied throughout
- Regular compliance scanning and reporting

## License

MIT
