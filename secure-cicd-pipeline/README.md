# Secure CI/CD Pipeline

This project demonstrates a secure CI/CD pipeline implementation with integrated security controls and vulnerability scanning.

## Features

- Automated vulnerability scanning of dependencies
- Static Application Security Testing (SAST) integration
- Dynamic Application Security Testing (DAST) integration
- Secret management with HashiCorp Vault
- Infrastructure as Code (IaC) security scanning
- Container image scanning
- Compliance as Code implementation

## Architecture

The pipeline implements a shift-left security approach, integrating security at every stage of the development lifecycle:

1. **Code Commit Stage**
   - Pre-commit hooks for secret detection
   - Code linting and formatting

2. **Build Stage**
   - SAST (Static Application Security Testing)
   - SCA (Software Composition Analysis)
   - Unit testing with security assertions

3. **Test Stage**
   - DAST (Dynamic Application Security Testing)
   - API security testing
   - Integration testing

4. **Deploy Stage**
   - IaC security validation
   - Container image scanning
   - Compliance checks

5. **Runtime**
   - Runtime application self-protection
   - Continuous monitoring
   - Automated incident response

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Git
- HashiCorp Vault
- Jenkins, GitLab CI, or GitHub Actions

### Installation

1. Clone this repository
2. Set up Vault for secret management
3. Configure your CI/CD tool of choice
4. Run the example pipeline

## Security Tools Integrated

- Dependency scanning: OWASP Dependency-Check, Snyk
- SAST: SonarQube, Checkmarx
- DAST: OWASP ZAP
- Container scanning: Trivy, Clair
- IaC scanning: Checkov, TFSec
- Secret management: HashiCorp Vault
- Compliance: InSpec, Open Policy Agent

## License

MIT
