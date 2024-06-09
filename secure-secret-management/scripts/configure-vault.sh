#!/bin/bash

# Script to configure the connection to HashiCorp Vault
# This script helps set up the connection parameters for the vault manager

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Vault Connection Configuration${NC}"
echo "This script will help you configure the connection to your vault server."
echo ""

# Default values
DEFAULT_VAULT_ADDR="http://127.0.0.1:8200"
DEFAULT_MOUNT_PATH="secret"
DEFAULT_BASE_PATH="windsurf-projects"

# Get configuration values with defaults
read -p "Vault server address [$DEFAULT_VAULT_ADDR]: " VAULT_ADDR
VAULT_ADDR=${VAULT_ADDR:-$DEFAULT_VAULT_ADDR}

read -p "Vault token file [~/.vault-token]: " TOKEN_FILE
TOKEN_FILE=${TOKEN_FILE:-"~/.vault-token"}

read -p "Vault mount path [$DEFAULT_MOUNT_PATH]: " MOUNT_PATH
MOUNT_PATH=${MOUNT_PATH:-$DEFAULT_MOUNT_PATH}

read -p "Base path for secrets [$DEFAULT_BASE_PATH]: " BASE_PATH
BASE_PATH=${BASE_PATH:-$DEFAULT_BASE_PATH}

# Get the root directory of the repository
ROOT_DIR=$(git rev-parse --show-toplevel 2>/dev/null || echo ".")

# Update the configuration file
CONFIG_FILE="$ROOT_DIR/config/vault-config.json"

echo -e "${YELLOW}Updating configuration in $CONFIG_FILE...${NC}"

# Use temporary file for the update
TMP_FILE=$(mktemp)

# Read the config file and update the values
jq --arg addr "$VAULT_ADDR" \
   --arg token "$TOKEN_FILE" \
   --arg mount "$MOUNT_PATH" \
   --arg base "$BASE_PATH" \
   '.rules[0].vault_config.address = $addr | 
    .rules[0].vault_config.token_file = $token | 
    .rules[0].vault_config.mount_path = $mount | 
    .rules[0].vault_config.base_path = $base' \
   "$CONFIG_FILE" > "$TMP_FILE"

# Replace the original file
mv "$TMP_FILE" "$CONFIG_FILE"

echo -e "${GREEN}Configuration updated successfully!${NC}"
echo ""
echo -e "${YELLOW}Testing connection to vault server...${NC}"

# Test the connection to vault
export VAULT_ADDR="$VAULT_ADDR"
if [ -f "${TOKEN_FILE/#\~/$HOME}" ]; then
  export VAULT_TOKEN=$(cat "${TOKEN_FILE/#\~/$HOME}")
fi

vault status > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo -e "${GREEN}Successfully connected to vault server!${NC}"
else
  echo -e "${YELLOW}Could not connect to vault server. Please check your configuration.${NC}"
  echo "You may need to:"
  echo "1. Start your vault server"
  echo "2. Ensure your vault token is valid"
  echo "3. Check network connectivity to the vault server"
fi

echo ""
echo -e "${BLUE}Configuration Summary:${NC}"
echo -e "Vault Address: ${GREEN}$VAULT_ADDR${NC}"
echo -e "Token File: ${GREEN}$TOKEN_FILE${NC}"
echo -e "Mount Path: ${GREEN}$MOUNT_PATH${NC}"
echo -e "Base Path: ${GREEN}$BASE_PATH${NC}"
echo ""
echo -e "${YELLOW}You can now use the vault manager to scan for and store secrets.${NC}"
