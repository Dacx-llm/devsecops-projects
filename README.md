# DevSecOps Projects Collection

This repository contains a collection of DevSecOps projects demonstrating various security practices, tools, and methodologies for secure software development and infrastructure management.

## Projects Overview

### 1. [Secure CI/CD Pipeline](./secure-cicd-pipeline)

A comprehensive implementation of a secure CI/CD pipeline with integrated security controls including:
- Automated vulnerability scanning of dependencies
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Secret management with HashiCorp Vault
- Infrastructure as Code (IaC) security scanning
- Container image scanning
- Compliance as Code implementation

### 2. [Secure Infrastructure as Code (IaC) with Terraform](./secure-iac-terraform)

Demonstrates secure Infrastructure as Code (IaC) practices using Terraform with:
- Secure Terraform modules for AWS, Azure, and GCP
- Automated IaC security scanning with Checkov, TFSec, and Terrascan
- Compliance as Code with Open Policy Agent (OPA)
- Secret management integration
- Drift detection and automated remediation

### 3. [Secure Container Platform](./secure-container-platform)

Showcases secure container practices, vulnerability scanning, and runtime security controls:
- Secure container image building with minimal base images
- Image vulnerability scanning with Trivy, Clair, and Grype
- Kubernetes security policies with OPA Gatekeeper
- Runtime security with Falco
- Network policies for pod-to-pod communication
- Secret management with sealed secrets

### 4. [Secure Secret Management](./secure-secret-management)

Implements a comprehensive secret management solution aligned with Windsurf Vault Management rules:
- Automated secret detection in code and configuration files
- Secure storage of secrets in HashiCorp Vault
- Intelligent organization of secrets by type and service
- Automatic replacement of hardcoded secrets with vault references
- Pre-commit hooks to prevent secret leakage
- CI/CD integration for continuous secret scanning

### 5. [Compliance as Code](./compliance-as-code)

Demonstrates how to implement Compliance as Code (CaC) principles to automate compliance checks:
- Automated compliance scanning for multiple frameworks (CIS, NIST, SOC2, HIPAA, GDPR, PCI DSS)
- Policy as Code implementation with Open Policy Agent (OPA)
- Continuous compliance monitoring in CI/CD pipelines
- Compliance reporting and dashboards
- Automated remediation for common compliance issues

## Getting Started

Each project contains its own README with detailed instructions on how to use and deploy the project. Navigate to the specific project directory to learn more.

## Common Features Across Projects

All projects in this collection implement:

1. **Shift-Left Security**: Integrating security early in the development lifecycle
2. **Automated Security Testing**: Continuous security testing in CI/CD pipelines
3. **Infrastructure as Code**: Managing infrastructure through code with security controls
4. **Compliance Automation**: Automating compliance checks and reporting
5. **Secret Management**: Secure handling of sensitive information
6. **Least Privilege Principle**: Implementing least privilege access controls
7. **Continuous Monitoring**: Real-time security monitoring and alerting

## Requirements

Different projects may have different requirements, but common dependencies include:

- Docker and Docker Compose
- Kubernetes cluster (local or cloud-based)
- Terraform >= 1.0.0
- HashiCorp Vault
- Git
- Various cloud provider CLIs (AWS, Azure, GCP)

## License

All projects in this collection are licensed under MIT.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
