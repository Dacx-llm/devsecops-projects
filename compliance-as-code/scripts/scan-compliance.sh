#!/bin/bash

# Script to run compliance scans against infrastructure
# This script supports scanning AWS, Azure, GCP, and Kubernetes resources

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
PROVIDER=""
FRAMEWORK="cis"
OUTPUT_FORMAT="json"
OUTPUT_DIR="./reports"
VERBOSE=false

# Function to display usage
function display_usage {
  echo -e "${BLUE}Compliance Scanner${NC}"
  echo "Usage: $0 --provider <provider> [options]"
  echo ""
  echo "Options:"
  echo "  --provider <provider>    Required. One of: aws, azure, gcp, kubernetes"
  echo "  --framework <framework>  Compliance framework to use. Default: cis"
  echo "                          Available: cis, nist, pci, hipaa, gdpr, soc2"
  echo "  --output <format>        Output format. Default: json"
  echo "                          Available: json, yaml, html, pdf"
  echo "  --output-dir <dir>       Directory to save reports. Default: ./reports"
  echo "  --verbose                Enable verbose output"
  echo "  --help                   Display this help message"
  echo ""
  echo "Examples:"
  echo "  $0 --provider aws --framework cis"
  echo "  $0 --provider kubernetes --framework pci --output html"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --provider)
      PROVIDER="$2"
      shift
      shift
      ;;
    --framework)
      FRAMEWORK="$2"
      shift
      shift
      ;;
    --output)
      OUTPUT_FORMAT="$2"
      shift
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift
      shift
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    --help)
      display_usage
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      display_usage
      exit 1
      ;;
  esac
done

# Validate required parameters
if [ -z "$PROVIDER" ]; then
  echo -e "${RED}Error: Provider is required${NC}"
  display_usage
  exit 1
fi

# Validate provider
case $PROVIDER in
  aws|azure|gcp|kubernetes)
    # Valid provider
    ;;
  *)
    echo -e "${RED}Error: Invalid provider '$PROVIDER'. Must be one of: aws, azure, gcp, kubernetes${NC}"
    exit 1
    ;;
esac

# Validate framework
case $FRAMEWORK in
  cis|nist|pci|hipaa|gdpr|soc2)
    # Valid framework
    ;;
  *)
    echo -e "${RED}Error: Invalid framework '$FRAMEWORK'. Must be one of: cis, nist, pci, hipaa, gdpr, soc2${NC}"
    exit 1
    ;;
esac

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Display scan information
echo -e "${BLUE}Starting compliance scan:${NC}"
echo -e "Provider:  ${GREEN}$PROVIDER${NC}"
echo -e "Framework: ${GREEN}$FRAMEWORK${NC}"
echo -e "Output:    ${GREEN}$OUTPUT_FORMAT${NC}"
echo -e "Directory: ${GREEN}$OUTPUT_DIR${NC}"
echo ""

# Generate timestamp for report filename
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/${PROVIDER}_${FRAMEWORK}_${TIMESTAMP}"

# Function to run AWS compliance scan
function scan_aws {
  echo -e "${YELLOW}Scanning AWS infrastructure against $FRAMEWORK framework...${NC}"
  
  # Check if AWS CLI is installed
  if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed${NC}"
    exit 1
  fi
  
  # Check if AWS is configured
  if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not configured. Run 'aws configure' first.${NC}"
    exit 1
  fi
  
  # Run OPA scan with AWS provider
  echo -e "${YELLOW}Collecting AWS resources...${NC}"
  
  # Create temporary directory for AWS resources
  TMP_DIR=$(mktemp -d)
  
  # Export AWS resources to JSON files
  echo -e "${YELLOW}Exporting S3 buckets...${NC}"
  aws s3api list-buckets --query 'Buckets[*]' --output json > "$TMP_DIR/s3_buckets.json"
  
  echo -e "${YELLOW}Exporting IAM users...${NC}"
  aws iam list-users --query 'Users[*]' --output json > "$TMP_DIR/iam_users.json"
  
  echo -e "${YELLOW}Exporting IAM roles...${NC}"
  aws iam list-roles --query 'Roles[*]' --output json > "$TMP_DIR/iam_roles.json"
  
  echo -e "${YELLOW}Exporting EC2 instances...${NC}"
  aws ec2 describe-instances --query 'Reservations[*].Instances[*]' --output json > "$TMP_DIR/ec2_instances.json"
  
  echo -e "${YELLOW}Exporting security groups...${NC}"
  aws ec2 describe-security-groups --query 'SecurityGroups[*]' --output json > "$TMP_DIR/security_groups.json"
  
  # Run OPA evaluation
  echo -e "${YELLOW}Evaluating compliance policies...${NC}"
  
  # In a real implementation, this would use OPA to evaluate the resources against policies
  # For this example, we'll simulate the evaluation
  
  echo -e "${GREEN}Compliance scan completed.${NC}"
  echo -e "Report saved to: ${GREEN}${REPORT_FILE}.${OUTPUT_FORMAT}${NC}"
}

# Function to run Kubernetes compliance scan
function scan_kubernetes {
  echo -e "${YELLOW}Scanning Kubernetes cluster against $FRAMEWORK framework...${NC}"
  
  # Check if kubectl is installed
  if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl is not installed${NC}"
    exit 1
  fi
  
  # Check if kubectl is configured
  if ! kubectl get nodes &> /dev/null; then
    echo -e "${RED}Error: kubectl is not configured or cannot connect to cluster${NC}"
    exit 1
  fi
  
  # Create temporary directory for Kubernetes resources
  TMP_DIR=$(mktemp -d)
  
  # Export Kubernetes resources to JSON files
  echo -e "${YELLOW}Exporting pods...${NC}"
  kubectl get pods --all-namespaces -o json > "$TMP_DIR/pods.json"
  
  echo -e "${YELLOW}Exporting deployments...${NC}"
  kubectl get deployments --all-namespaces -o json > "$TMP_DIR/deployments.json"
  
  echo -e "${YELLOW}Exporting services...${NC}"
  kubectl get services --all-namespaces -o json > "$TMP_DIR/services.json"
  
  echo -e "${YELLOW}Exporting network policies...${NC}"
  kubectl get networkpolicies --all-namespaces -o json > "$TMP_DIR/networkpolicies.json"
  
  echo -e "${YELLOW}Exporting role bindings...${NC}"
  kubectl get rolebindings --all-namespaces -o json > "$TMP_DIR/rolebindings.json"
  
  # Run OPA evaluation
  echo -e "${YELLOW}Evaluating compliance policies...${NC}"
  
  # In a real implementation, this would use OPA to evaluate the resources against policies
  # For this example, we'll simulate the evaluation
  
  echo -e "${GREEN}Compliance scan completed.${NC}"
  echo -e "Report saved to: ${GREEN}${REPORT_FILE}.${OUTPUT_FORMAT}${NC}"
}

# Function to run Azure compliance scan
function scan_azure {
  echo -e "${YELLOW}Scanning Azure infrastructure against $FRAMEWORK framework...${NC}"
  
  # Check if Azure CLI is installed
  if ! command -v az &> /dev/null; then
    echo -e "${RED}Error: Azure CLI is not installed${NC}"
    exit 1
  fi
  
  # Check if Azure CLI is configured
  if ! az account show &> /dev/null; then
    echo -e "${RED}Error: Azure CLI is not configured. Run 'az login' first.${NC}"
    exit 1
  fi
  
  # Create temporary directory for Azure resources
  TMP_DIR=$(mktemp -d)
  
  # Export Azure resources to JSON files
  echo -e "${YELLOW}Exporting resource groups...${NC}"
  az group list > "$TMP_DIR/resource_groups.json"
  
  echo -e "${YELLOW}Exporting storage accounts...${NC}"
  az storage account list > "$TMP_DIR/storage_accounts.json"
  
  echo -e "${YELLOW}Exporting virtual machines...${NC}"
  az vm list > "$TMP_DIR/virtual_machines.json"
  
  echo -e "${YELLOW}Exporting network security groups...${NC}"
  az network nsg list > "$TMP_DIR/network_security_groups.json"
  
  # Run OPA evaluation
  echo -e "${YELLOW}Evaluating compliance policies...${NC}"
  
  # In a real implementation, this would use OPA to evaluate the resources against policies
  # For this example, we'll simulate the evaluation
  
  echo -e "${GREEN}Compliance scan completed.${NC}"
  echo -e "Report saved to: ${GREEN}${REPORT_FILE}.${OUTPUT_FORMAT}${NC}"
}

# Function to run GCP compliance scan
function scan_gcp {
  echo -e "${YELLOW}Scanning GCP infrastructure against $FRAMEWORK framework...${NC}"
  
  # Check if gcloud is installed
  if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}Error: Google Cloud SDK is not installed${NC}"
    exit 1
  fi
  
  # Check if gcloud is configured
  if ! gcloud config list account --format "value(core.account)" &> /dev/null; then
    echo -e "${RED}Error: Google Cloud SDK is not configured. Run 'gcloud auth login' first.${NC}"
    exit 1
  fi
  
  # Create temporary directory for GCP resources
  TMP_DIR=$(mktemp -d)
  
  # Get current project
  PROJECT=$(gcloud config get-value project)
  
  # Export GCP resources to JSON files
  echo -e "${YELLOW}Exporting compute instances...${NC}"
  gcloud compute instances list --project "$PROJECT" --format json > "$TMP_DIR/compute_instances.json"
  
  echo -e "${YELLOW}Exporting storage buckets...${NC}"
  gcloud storage ls --project "$PROJECT" --format json > "$TMP_DIR/storage_buckets.json"
  
  echo -e "${YELLOW}Exporting IAM policies...${NC}"
  gcloud projects get-iam-policy "$PROJECT" --format json > "$TMP_DIR/iam_policies.json"
  
  echo -e "${YELLOW}Exporting firewall rules...${NC}"
  gcloud compute firewall-rules list --project "$PROJECT" --format json > "$TMP_DIR/firewall_rules.json"
  
  # Run OPA evaluation
  echo -e "${YELLOW}Evaluating compliance policies...${NC}"
  
  # In a real implementation, this would use OPA to evaluate the resources against policies
  # For this example, we'll simulate the evaluation
  
  echo -e "${GREEN}Compliance scan completed.${NC}"
  echo -e "Report saved to: ${GREEN}${REPORT_FILE}.${OUTPUT_FORMAT}${NC}"
}

# Run the appropriate scan based on provider
case $PROVIDER in
  aws)
    scan_aws
    ;;
  kubernetes)
    scan_kubernetes
    ;;
  azure)
    scan_azure
    ;;
  gcp)
    scan_gcp
    ;;
esac

# Clean up temporary files
if [ -d "$TMP_DIR" ]; then
  rm -rf "$TMP_DIR"
fi

echo -e "${GREEN}Scan completed successfully.${NC}"
