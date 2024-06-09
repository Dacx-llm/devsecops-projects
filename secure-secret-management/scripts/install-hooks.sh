#!/bin/bash

# Script to install git hooks for the secure secret management project

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Installing git hooks...${NC}"

# Get the root directory of the repository
ROOT_DIR=$(git rev-parse --show-toplevel)

# Create hooks directory if it doesn't exist
mkdir -p "$ROOT_DIR/.git/hooks"

# Copy pre-commit hook
cp "$ROOT_DIR/scripts/pre-commit-hook.sh" "$ROOT_DIR/.git/hooks/pre-commit"

# Make hooks executable
chmod +x "$ROOT_DIR/.git/hooks/pre-commit"

echo -e "${GREEN}Git hooks installed successfully!${NC}"
echo -e "${YELLOW}Pre-commit hook will now scan for secrets before each commit.${NC}"
