# Secure Secret Management

This project implements a comprehensive secret management solution that automatically detects, stores, and manages sensitive data in development environments. It's designed to work with the Windsurf Vault Management system to provide secure handling of API keys, passwords, certificates, and other secrets.

## Features

- Automated secret detection in code and configuration files
- Secure storage of secrets in HashiCorp Vault
- Intelligent organization of secrets by type and service
- Automatic replacement of hardcoded secrets with vault references
- Pre-commit hooks to prevent secret leakage
- CI/CD integration for continuous secret scanning
- Support for multiple vault backends (HashiCorp Vault, pass, custom)
- Audit logging and access control

## Architecture

The solution implements a layered approach to secret management:

1. **Detection Layer**
   - Pattern-based secret detection
   - Git history scanning
   - Pre-commit hooks
   - Continuous monitoring

2. **Storage Layer**
   - HashiCorp Vault integration
   - Hierarchical secret organization
   - Automatic path creation
   - Encryption at rest

3. **Access Layer**
   - Fine-grained access control
   - Temporary credentials
   - Audit logging
   - Rotation policies

4. **Integration Layer**
   - CI/CD pipeline integration
   - IDE plugins
   - CLI tools
   - Application integration

## Getting Started

### Prerequisites

- HashiCorp Vault server
- Git
- Node.js (for the CLI tools)
- Python 3.8+ (for the detection scripts)

### Installation

1. Clone this repository
2. Install dependencies:

```bash
npm install
```

3. Configure your vault connection:

```bash
./configure-vault.sh
```

4. Set up the pre-commit hooks:

```bash
./install-hooks.sh
```

## Usage

### Scanning for Secrets

```bash
npm run scan -- --path=/path/to/project
```

### Storing Secrets in Vault

```bash
npm run store-secrets -- --config=config.json
```

### Replacing Secrets with References

```bash
npm run replace-secrets -- --path=/path/to/project
```

### Validating Secret References

```bash
npm run validate -- --path=/path/to/project
```

## Configuration

The project uses a configuration file to define secret patterns, vault paths, and other settings:

```json
{
  "vaultBackend": "hashicorp",
  "vaultAddress": "http://127.0.0.1:8200",
  "mountPath": "secret",
  "basePath": "windsurf-projects",
  "secretPatterns": {
    "api_keys": {
      "patterns": [
        "(?i)(api[_-]?key|apikey)\\s*[=:]\\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?"
      ],
      "vault_path": "api-keys"
    },
    "database_credentials": {
      "patterns": [
        "(?i)(db[_-]?password|database[_-]?password)\\s*[=:]\\s*['\"]?([^'\"\\s]{8,})['\"]?"
      ],
      "vault_path": "database"
    }
  }
}
```

## Integration with CI/CD

The project includes GitHub Actions workflows for:
- Scanning repositories for secrets
- Validating secret references
- Monitoring for secret leakage
- Generating compliance reports

## Security Controls

- All secrets are encrypted at rest in Vault
- Access to secrets requires authentication and authorization
- All access is logged and auditable
- Secrets are automatically rotated based on policies
- Least privilege principle is applied throughout

## License

MIT
