#!/bin/bash

# Pre-commit hook to detect and prevent secrets from being committed
# This script is installed by the install-hooks.sh script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Running secret detection pre-commit hook...${NC}"

# Get the root directory of the repository
ROOT_DIR=$(git rev-parse --show-toplevel)

# Run the vault manager script to scan staged files
NODE_PATH="$ROOT_DIR/node_modules" node "$ROOT_DIR/scripts/vault-manager.js" --scan --staged-only

# Check the exit code
if [ $? -ne 0 ]; then
  echo -e "${RED}Error: Secrets detected in staged files!${NC}"
  echo -e "${YELLOW}Please run 'npm run store-secrets' to securely store these secrets in vault${NC}"
  echo -e "${YELLOW}or remove them from your changes before committing.${NC}"
  exit 1
fi

echo -e "${GREEN}No secrets detected in staged files.${NC}"
exit 0
