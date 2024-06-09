package compliance.kubernetes.pod_security

# CIS Kubernetes 5.2.1: Minimize the admission of privileged containers
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.privileged
  
  msg := sprintf("CIS 5.2.1 Violation: Privileged container '%v' is not allowed", [container.name])
}

# CIS Kubernetes 5.2.2: Minimize the admission of containers wishing to share the host process ID namespace
deny[msg] {
  input.kind == "Pod"
  input.spec.hostPID
  
  msg := sprintf("CIS 5.2.2 Violation: Pod '%v' should not use host PID namespace", [input.metadata.name])
}

# CIS Kubernetes 5.2.3: Minimize the admission of containers wishing to share the host IPC namespace
deny[msg] {
  input.kind == "Pod"
  input.spec.hostIPC
  
  msg := sprintf("CIS 5.2.3 Violation: Pod '%v' should not use host IPC namespace", [input.metadata.name])
}

# CIS Kubernetes 5.2.4: Minimize the admission of containers wishing to share the host network namespace
deny[msg] {
  input.kind == "Pod"
  input.spec.hostNetwork
  
  msg := sprintf("CIS 5.2.4 Violation: Pod '%v' should not use host network namespace", [input.metadata.name])
}

# CIS Kubernetes 5.2.5: Minimize the admission of containers with allowPrivilegeEscalation
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation
  
  msg := sprintf("CIS 5.2.5 Violation: Container '%v' should not allow privilege escalation", [container.name])
}

# CIS Kubernetes 5.2.6: Minimize the admission of root containers
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not container.securityContext.runAsNonRoot
  
  msg := sprintf("CIS 5.2.6 Violation: Container '%v' should set runAsNonRoot to true", [container.name])
}

# CIS Kubernetes 5.2.7: Minimize the admission of containers with the NET_RAW capability
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not has_dropped_capability(container, "NET_RAW")
  
  msg := sprintf("CIS 5.2.7 Violation: Container '%v' should drop NET_RAW capability", [container.name])
}

# CIS Kubernetes 5.2.8: Minimize the admission of containers with added capabilities
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.capabilities.add
  
  msg := sprintf("CIS 5.2.8 Violation: Container '%v' should not add capabilities", [container.name])
}

# CIS Kubernetes 5.2.9: Minimize the admission of containers with capabilities assigned
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not container.securityContext.capabilities.drop
  
  msg := sprintf("CIS 5.2.9 Violation: Container '%v' should drop ALL capabilities and add only those required", [container.name])
}

# CIS Kubernetes 5.7.1: Ensure that the seccomp profile is set to docker/default or runtime/default
deny[msg] {
  input.kind == "Pod"
  not pod_has_seccomp(input)
  
  msg := sprintf("CIS 5.7.1 Violation: Pod '%v' should set seccomp profile to runtime/default", [input.metadata.name])
}

# CIS Kubernetes 5.7.2: Ensure that the seccomp profile is set to docker/default in your pod definitions
deny[msg] {
  input.kind == "Pod"
  not pod_has_seccomp(input)
  
  msg := sprintf("CIS 5.7.2 Violation: Pod '%v' should set seccomp profile to docker/default or runtime/default", [input.metadata.name])
}

# CIS Kubernetes 5.7.3: Apply Security Context to Your Pods and Containers
deny[msg] {
  input.kind == "Pod"
  not input.spec.securityContext
  
  msg := sprintf("CIS 5.7.3 Violation: Pod '%v' should set a security context", [input.metadata.name])
}

# PCI-DSS 6.5.8: Ensure pods running payment applications have appropriate security contexts
deny[msg] {
  input.kind == "Pod"
  is_payment_app(input)
  container := input.spec.containers[_]
  
  not container.securityContext.readOnlyRootFilesystem
  
  msg := sprintf("PCI-DSS 6.5.8 Violation: Payment application container '%v' should have readOnlyRootFilesystem set to true", [container.name])
}

# HIPAA: Ensure pods processing PHI have appropriate security controls
deny[msg] {
  input.kind == "Pod"
  processes_phi(input)
  
  not input.spec.securityContext.runAsNonRoot
  
  msg := sprintf("HIPAA Violation: Pod '%v' processing PHI should run as non-root", [input.metadata.name])
}

# Helper functions
has_dropped_capability(container, cap) {
  container.securityContext.capabilities.drop[_] == cap
}

has_dropped_capability(container, cap) {
  container.securityContext.capabilities.drop[_] == "ALL"
}

pod_has_seccomp(pod) {
  pod.metadata.annotations["seccomp.security.alpha.kubernetes.io/pod"] == "runtime/default"
}

pod_has_seccomp(pod) {
  pod.metadata.annotations["container.seccomp.security.alpha.kubernetes.io/pod"] == "runtime/default"
}

pod_has_seccomp(pod) {
  pod.spec.securityContext.seccompProfile.type == "RuntimeDefault"
}

is_payment_app(pod) {
  pod.metadata.labels.app == "payment"
}

is_payment_app(pod) {
  pod.metadata.labels.component == "payment"
}

is_payment_app(pod) {
  pod.metadata.labels["pci-dss"] == "in-scope"
}

processes_phi(pod) {
  pod.metadata.labels.data == "phi"
}

processes_phi(pod) {
  pod.metadata.labels.hipaa == "in-scope"
}

processes_phi(pod) {
  pod.metadata.labels.component == "medical-records"
}
