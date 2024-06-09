#!/usr/bin/env node

/**
 * Vault Reference Validator
 * 
 * This script validates vault references in files to ensure they are properly formatted
 * and point to existing secrets in the vault.
 */

const fs = require('fs');
const path = require('path');
const util = require('util');
const { exec } = require('child_process');
const execAsync = util.promisify(exec);
const readFile = util.promisify(fs.readFile);
const glob = util.promisify(require('glob'));

// Load configuration
const configPath = path.join(__dirname, '../config/vault-config.json');
let config = {};

try {
  const configData = fs.readFileSync(configPath, 'utf8');
  config = JSON.parse(configData);
} catch (error) {
  console.error(`Error loading configuration: ${error.message}`);
  process.exit(1);
}

// Extract vault configuration
const vaultConfig = config.rules[0].vault_config;

class VaultReferenceValidator {
  constructor(options = {}) {
    this.vaultAddress = options.address || 'http://127.0.0.1:8200';
    this.vaultToken = this.loadVaultToken(options.tokenFile);
    this.mountPath = options.mountPath || 'secret';
    this.basePath = options.basePath || 'windsurf-projects';
    this.projectName = options.projectName || path.basename(process.cwd());
    
    console.log(`Vault Reference Validator initialized for project: ${this.projectName}`);
    console.log(`Using vault at ${this.vaultAddress}`);
  }

  /**
   * Load the vault token from the specified file
   */
  loadVaultToken(tokenFile) {
    const defaultTokenFile = '~/.vault-token';
    const file = tokenFile || defaultTokenFile;
    const expandedPath = file.replace(/^~/, process.env.HOME || process.env.USERPROFILE);
    
    try {
      if (fs.existsSync(expandedPath)) {
        return fs.readFileSync(expandedPath, 'utf8').trim();
      }
    } catch (error) {
      console.warn(`Warning: Could not read vault token from ${expandedPath}`);
    }
    
    // Try environment variable as fallback
    return process.env.VAULT_TOKEN || '';
  }

  /**
   * Verify connection to the vault server
   */
  async verifyVaultConnection() {
    try {
      const result = await this.executeVaultCommand(['status', '-format=json']);
      const status = JSON.parse(result.stdout);
      
      if (status.sealed) {
        throw new Error('Vault is sealed and cannot be used');
      }
      
      console.log('✅ Successfully connected to Vault server');
      return true;
    } catch (error) {
      console.error('❌ Failed to connect to Vault server:', error.message);
      return false;
    }
  }

  /**
   * Execute a vault CLI command
   */
  async executeVaultCommand(args) {
    const env = {
      ...process.env,
      VAULT_ADDR: this.vaultAddress,
      VAULT_TOKEN: this.vaultToken,
      VAULT_FORMAT: 'json'
    };
    
    try {
      return await execAsync(`vault ${args.join(' ')}`, { env });
    } catch (error) {
      console.error(`Error executing vault command: ${args.join(' ')}`);
      throw error;
    }
  }

  /**
   * Find files with vault references
   */
  async findFilesWithReferences(directory) {
    const filePatterns = config.rules[0].trigger.file_patterns;
    const files = [];
    
    for (const pattern of filePatterns) {
      const matches = await glob(pattern, { cwd: directory, absolute: true });
      files.push(...matches);
    }
    
    return [...new Set(files)]; // Remove duplicates
  }

  /**
   * Validate vault references in a file
   */
  async validateReferencesInFile(filePath) {
    try {
      const content = await readFile(filePath, 'utf8');
      const referencePattern = /\{\{vault:([^:]+):([^}]+)\}\}/g;
      let match;
      const results = {
        file: filePath,
        valid: true,
        references: [],
        errors: []
      };
      
      while ((match = referencePattern.exec(content)) !== null) {
        const [fullMatch, vaultPath, secretKey] = match;
        
        try {
          // Check if the secret exists in vault
          await this.executeVaultCommand(['kv', 'get', vaultPath, '-field=' + secretKey]);
          
          results.references.push({
            path: vaultPath,
            key: secretKey,
            valid: true
          });
        } catch (error) {
          results.valid = false;
          results.errors.push(`Invalid reference: ${fullMatch} - Secret not found in vault`);
          
          results.references.push({
            path: vaultPath,
            key: secretKey,
            valid: false,
            error: error.message
          });
        }
      }
      
      return results;
    } catch (error) {
      return {
        file: filePath,
        valid: false,
        references: [],
        errors: [`Error reading file: ${error.message}`]
      };
    }
  }

  /**
   * Validate all vault references in the project
   */
  async validateAllReferences(directory) {
    console.log(`Validating vault references in ${directory}...`);
    
    // Find files with potential references
    const files = await this.findFilesWithReferences(directory);
    console.log(`Found ${files.length} files to check for vault references.`);
    
    const results = {
      totalFiles: files.length,
      filesWithReferences: 0,
      validReferences: 0,
      invalidReferences: 0,
      fileResults: []
    };
    
    // Validate references in each file
    for (const file of files) {
      const fileResult = await this.validateReferencesInFile(file);
      
      if (fileResult.references.length > 0) {
        results.filesWithReferences++;
        results.fileResults.push(fileResult);
        
        // Count valid and invalid references
        const validCount = fileResult.references.filter(ref => ref.valid).length;
        const invalidCount = fileResult.references.filter(ref => !ref.valid).length;
        
        results.validReferences += validCount;
        results.invalidReferences += invalidCount;
        
        // Log results for this file
        if (fileResult.valid) {
          console.log(`✅ ${file}: ${validCount} valid references`);
        } else {
          console.log(`❌ ${file}: ${validCount} valid references, ${invalidCount} invalid references`);
          for (const error of fileResult.errors) {
            console.log(`  - ${error}`);
          }
        }
      }
    }
    
    // Log summary
    console.log('\nValidation Summary:');
    console.log(`Total files checked: ${results.totalFiles}`);
    console.log(`Files with references: ${results.filesWithReferences}`);
    console.log(`Valid references: ${results.validReferences}`);
    console.log(`Invalid references: ${results.invalidReferences}`);
    
    return results;
  }

  /**
   * Main method to run the validator
   */
  async run(options) {
    const { projectDir } = options;
    const directory = projectDir || process.cwd();
    
    // Verify vault connection
    const connected = await this.verifyVaultConnection();
    if (!connected) {
      console.error('Aborting due to vault connection failure.');
      process.exit(1);
    }
    
    // Validate references
    const results = await this.validateAllReferences(directory);
    
    // Exit with error if there are invalid references
    if (results.invalidReferences > 0) {
      console.error(`\n❌ Found ${results.invalidReferences} invalid vault references.`);
      process.exit(1);
    } else {
      console.log(`\n✅ All ${results.validReferences} vault references are valid.`);
    }
    
    return results;
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  projectDir: args.includes('--path') ? args[args.indexOf('--path') + 1] : null
};

// Initialize and run the validator
const validator = new VaultReferenceValidator({
  address: vaultConfig.address,
  tokenFile: vaultConfig.token_file,
  mountPath: vaultConfig.mount_path,
  basePath: vaultConfig.base_path
});

validator.run(options).catch(error => {
  console.error(`Error running validator: ${error.message}`);
  process.exit(1);
});

module.exports = VaultReferenceValidator;
