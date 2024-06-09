# Compliance as Code

This project demonstrates how to implement Compliance as Code (CaC) principles to automate compliance checks, reporting, and remediation across cloud infrastructure, applications, and development practices.

## Features

- Automated compliance scanning for multiple frameworks (CIS, NIST, SOC2, HIPAA, GDPR, PCI DSS)
- Policy as Code implementation with Open Policy Agent (OPA)
- Continuous compliance monitoring in CI/CD pipelines
- Compliance reporting and dashboards
- Automated remediation for common compliance issues
- Audit-ready evidence collection
- Multi-cloud compliance controls (AWS, Azure, GCP)

## Architecture

The solution implements a layered approach to compliance automation:

1. **Policy Layer**
   - Compliance frameworks defined as code
   - Policy rules in Rego language
   - Version-controlled compliance requirements
   - Centralized policy management

2. **Assessment Layer**
   - Automated compliance scanning
   - Continuous monitoring
   - Evidence collection
   - Gap analysis

3. **Reporting Layer**
   - Compliance dashboards
   - Audit-ready reports
   - Trend analysis
   - Risk assessment

4. **Remediation Layer**
   - Automated fixes for compliance issues
   - Self-healing infrastructure
   - Drift detection and correction
   - Compliance enforcement

## Supported Compliance Frameworks

- CIS Benchmarks (AWS, Azure, GCP, Kubernetes)
- NIST 800-53
- SOC2 Type II
- HIPAA
- GDPR
- PCI DSS
- ISO 27001
- FedRAMP

## Getting Started

### Prerequisites

- Terraform >= 1.0.0
- Docker and Docker Compose
- Python 3.8+
- AWS/Azure/GCP CLI tools
- OPA (Open Policy Agent)

### Installation

1. Clone this repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure your cloud provider credentials
4. Initialize the compliance baseline:

```bash
./scripts/initialize-compliance.sh
```

## Usage

### Running Compliance Scans

```bash
# Scan AWS infrastructure
./scripts/scan-compliance.sh --provider aws --framework cis

# Scan Kubernetes cluster
./scripts/scan-compliance.sh --provider kubernetes --framework cis

# Generate compliance report
./scripts/generate-report.sh --output pdf
```

### Integrating with CI/CD

The project includes GitHub Actions workflows for:
- Running compliance checks on infrastructure changes
- Validating compliance before deployment
- Generating compliance reports
- Collecting evidence for audits

### Customizing Compliance Policies

Policies are defined in the `policies` directory using Rego language:

```rego
package compliance.cis.aws.s3

# CIS AWS 2.1.5: Ensure S3 buckets are configured with 'Block public access'
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  not input.resource.aws_s3_bucket_public_access_block
  
  msg := sprintf("S3 bucket '%v' does not have public access blocks configured", [input.resource.aws_s3_bucket.id])
}
```

## Project Structure

```
.
├── policies/                  # Compliance policies in Rego
│   ├── aws/                   # AWS-specific policies
│   ├── azure/                 # Azure-specific policies
│   ├── gcp/                   # GCP-specific policies
│   ├── kubernetes/            # Kubernetes policies
│   └── common/                # Cross-platform policies
├── scanners/                  # Compliance scanning tools
├── remediation/               # Automated remediation scripts
├── reports/                   # Report templates and generators
├── evidence/                  # Evidence collection tools
├── dashboards/                # Compliance dashboards
└── .github/workflows/         # CI/CD integration
```

## Compliance Controls

The project implements controls across several categories:

- **Identity and Access Management**
  - Authentication controls
  - Authorization policies
  - Privilege management
  - Access reviews

- **Data Protection**
  - Encryption at rest and in transit
  - Data classification
  - Data retention policies
  - Secure deletion

- **Network Security**
  - Network segmentation
  - Firewall rules
  - Traffic monitoring
  - DDoS protection

- **Logging and Monitoring**
  - Audit logging
  - Alert configuration
  - Log retention
  - Incident response

- **Change Management**
  - Change approval processes
  - Version control
  - Configuration management
  - Backup and recovery

## License

MIT
