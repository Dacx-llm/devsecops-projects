# Secure Container Platform

This project demonstrates secure container practices, vulnerability scanning, and runtime security controls for containerized applications in a Kubernetes environment.

## Features

- Secure container image building with minimal base images
- Image vulnerability scanning with Trivy, Clair, and Grype
- Kubernetes security policies with OPA Gatekeeper
- Runtime security with Falco
- Network policies for pod-to-pod communication
- Secret management with sealed secrets
- Service mesh security with Istio
- Continuous security monitoring and alerting

## Architecture

The platform implements a defense-in-depth approach to container security:

1. **Build-Time Security**
   - Minimal base images
   - Multi-stage builds
   - No unnecessary packages
   - Non-root users
   - Image scanning

2. **Deploy-Time Security**
   - Admission controllers
   - Policy enforcement
   - Resource limits
   - Network policies
   - Secret management

3. **Runtime Security**
   - Behavioral monitoring
   - Anomaly detection
   - Container isolation
   - Privilege restriction
   - Audit logging

## Components

### 1. Secure Base Images

The project includes secure base images for common application types:
- Minimal Node.js
- Minimal Python
- Minimal Java
- Minimal Go

### 2. Security Policies

- OPA Gatekeeper policies for Kubernetes
- Network policies for pod isolation
- Pod Security Policies (or Pod Security Standards)
- Resource quotas and limits

### 3. Monitoring & Detection

- Falco rules for runtime security monitoring
- Prometheus alerts for security events
- ELK stack for security log analysis
- Grafana dashboards for security visualization

## Getting Started

### Prerequisites

- Docker
- Kubernetes cluster (minikube, kind, or cloud provider)
- kubectl
- Helm

### Installation

1. Clone this repository
2. Deploy the security components:

```bash
# Deploy OPA Gatekeeper
kubectl apply -f kubernetes/gatekeeper/

# Deploy Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco

# Deploy network policies
kubectl apply -f kubernetes/network-policies/

# Deploy sealed secrets
kubectl apply -f kubernetes/sealed-secrets/
```

3. Build and deploy the example applications:

```bash
# Build secure images
docker build -t secure-nodejs-app:latest -f dockerfiles/nodejs.Dockerfile .
docker build -t secure-python-app:latest -f dockerfiles/python.Dockerfile .

# Deploy applications
kubectl apply -f kubernetes/applications/
```

## Security Controls

### Image Security

- Minimal base images (Alpine, Distroless)
- Multi-stage builds to reduce image size
- No unnecessary packages or tools
- Non-root users
- Read-only file systems
- No privileged access

### Kubernetes Security

- Pod Security Standards (restricted profile)
- Network policies for pod isolation
- Resource limits to prevent DoS
- RBAC for access control
- Secrets management with sealed secrets
- Admission controllers for policy enforcement

### Runtime Security

- Falco for runtime monitoring
- Seccomp profiles
- AppArmor profiles
- Audit logging
- Behavioral monitoring

## CI/CD Integration

The project includes GitHub Actions workflows for:
- Building secure container images
- Scanning images for vulnerabilities
- Validating Kubernetes manifests
- Deploying with security controls
- Continuous security monitoring

## License

MIT
