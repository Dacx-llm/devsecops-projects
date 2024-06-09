#!/usr/bin/env node

/**
 * Vault Manager Script
 * 
 * This script handles the detection, storage, and management of secrets
 * according to the Windsurf Vault Management rules.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync, spawn } = require('child_process');
const util = require('util');
const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);
const exec = util.promisify(require('child_process').exec);

class VaultManager {
  constructor(options = {}) {
    this.vaultBackend = options.backend || 'hashicorp';
    this.vaultAddress = options.address || 'http://127.0.0.1:8200';
    this.vaultToken = this.loadVaultToken(options.tokenFile);
    this.mountPath = options.mountPath || 'secret';
    this.basePath = options.basePath || 'windsurf-projects';
    this.projectName = options.projectName || path.basename(process.cwd());
    this.backupDir = '.windsurf/backups';
    
    // Initialize secret patterns from config
    this.secretPatterns = options.secretPatterns || {};
    
    // Create backup directory if it doesn't exist
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
    
    console.log(`Vault Manager initialized for project: ${this.projectName}`);
    console.log(`Using vault backend: ${this.vaultBackend} at ${this.vaultAddress}`);
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
      return await exec(`vault ${args.join(' ')}`, { env });
    } catch (error) {
      console.error(`Error executing vault command: ${args.join(' ')}`);
      throw error;
    }
  }

  /**
   * Scan files for secrets based on configured patterns
   */
  async scanForSecrets(directory) {
    console.log(`Scanning ${directory} for secrets...`);
    
    const results = {
      totalFiles: 0,
      secretsFound: 0,
      secretsByType: {},
      secretLocations: []
    };
    
    // Get all files matching the patterns from config
    const files = await this.getFilesToScan(directory);
    results.totalFiles = files.length;
    
    for (const file of files) {
      try {
        const content = await readFile(file, 'utf8');
        const fileSecrets = await this.detectSecretsInContent(content, file);
        
        if (fileSecrets.length > 0) {
          results.secretsFound += fileSecrets.length;
          results.secretLocations.push({
            file,
            secrets: fileSecrets
          });
          
          // Organize secrets by type
          for (const secret of fileSecrets) {
            if (!results.secretsByType[secret.type]) {
              results.secretsByType[secret.type] = [];
            }
            results.secretsByType[secret.type].push(secret);
          }
        }
      } catch (error) {
        console.warn(`Warning: Could not scan ${file}: ${error.message}`);
      }
    }
    
    console.log(`Scan completed. Found ${results.secretsFound} secrets in ${results.totalFiles} files.`);
    return results;
  }

  /**
   * Get all files to scan based on configured patterns
   */
  async getFilesToScan(directory) {
    // This is a simplified implementation. In a real-world scenario,
    // you would use glob patterns from the config to find files.
    const allFiles = [];
    
    const walkDir = (dir) => {
      const files = fs.readdirSync(dir);
      
      for (const file of files) {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        
        if (stat.isDirectory() && !file.startsWith('.')) {
          walkDir(filePath);
        } else if (stat.isFile()) {
          // Check if file matches any of the configured patterns
          const ext = path.extname(file).toLowerCase();
          if (['.env', '.json', '.yaml', '.yml', '.js', '.ts', '.py', '.php', '.rb', '.go'].includes(ext) ||
              file.startsWith('.env')) {
            allFiles.push(filePath);
          }
        }
      }
    };
    
    walkDir(directory);
    return allFiles;
  }

  /**
   * Detect secrets in file content based on configured patterns
   */
  async detectSecretsInContent(content, filePath) {
    const detectedSecrets = [];
    
    // Check each secret type and its patterns
    for (const [type, config] of Object.entries(this.secretPatterns)) {
      for (const patternStr of config.patterns) {
        const pattern = new RegExp(patternStr, 'g');
        let match;
        
        while ((match = pattern.exec(content)) !== null) {
          // The second capture group contains the secret value
          const secretValue = match[2] || match[0];
          const secretKey = this.generateSecretKey(filePath, match[1] || type);
          
          detectedSecrets.push({
            type,
            key: secretKey,
            value: secretValue,
            path: filePath,
            vaultPath: config.vault_path || type,
            match: match[0],
            lineNumber: this.getLineNumber(content, match.index)
          });
        }
      }
    }
    
    return detectedSecrets;
  }

  /**
   * Generate a key for storing the secret in vault
   */
  generateSecretKey(filePath, identifier) {
    const fileName = path.basename(filePath);
    const dirName = path.basename(path.dirname(filePath));
    
    // Clean up the identifier
    const cleanIdentifier = identifier
      .replace(/[_-]?key$|[_-]?secret$|[_-]?token$|[_-]?password$/i, '')
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .toLowerCase();
    
    return `${dirName}_${fileName}_${cleanIdentifier}`;
  }

  /**
   * Get the line number for a position in the content
   */
  getLineNumber(content, position) {
    const lines = content.substring(0, position).split('\n');
    return lines.length;
  }

  /**
   * Store detected secrets in vault
   */
  async storeSecrets(scanResults) {
    if (!scanResults || scanResults.secretsFound === 0) {
      console.log('No secrets to store.');
      return;
    }
    
    console.log(`Storing ${scanResults.secretsFound} secrets in vault...`);
    
    // Ensure vault paths exist
    await this.createVaultPaths(scanResults);
    
    // Store each secret
    for (const location of scanResults.secretLocations) {
      for (const secret of location.secrets) {
        try {
          const vaultPath = `${this.mountPath}/${this.basePath}/${this.projectName}/${secret.vaultPath}`;
          const secretData = {
            value: secret.value,
            metadata: {
              file: secret.path,
              line: secret.lineNumber,
              detected_at: new Date().toISOString(),
              type: secret.type
            }
          };
          
          // Store secret in vault
          await this.executeVaultCommand([
            'kv',
            'put',
            vaultPath,
            `${secret.key}=${secret.value}`
          ]);
          
          console.log(`✅ Stored secret: ${vaultPath}/${secret.key}`);
        } catch (error) {
          console.error(`❌ Failed to store secret ${secret.key}: ${error.message}`);
        }
      }
    }
    
    console.log('Secret storage completed.');
  }

  /**
   * Create vault paths for storing secrets
   */
  async createVaultPaths(scanResults) {
    const uniquePaths = new Set();
    
    // Collect all unique vault paths
    for (const [type, secrets] of Object.entries(scanResults.secretsByType)) {
      for (const secret of secrets) {
        uniquePaths.add(`${this.mountPath}/${this.basePath}/${this.projectName}/${secret.vaultPath}`);
      }
    }
    
    // Create each path
    for (const path of uniquePaths) {
      try {
        // Check if path exists
        try {
          await this.executeVaultCommand(['kv', 'list', path]);
          console.log(`Path already exists: ${path}`);
        } catch (error) {
          // Path doesn't exist, create it
          // Note: In HashiCorp Vault, paths are created automatically when storing secrets
          console.log(`Creating path: ${path}`);
        }
      } catch (error) {
        console.error(`❌ Failed to create path ${path}: ${error.message}`);
      }
    }
  }

  /**
   * Replace secrets in files with vault references
   */
  async replaceSecretsWithReferences(scanResults) {
    if (!scanResults || scanResults.secretsFound === 0) {
      console.log('No secrets to replace.');
      return;
    }
    
    console.log(`Replacing ${scanResults.secretsFound} secrets with vault references...`);
    
    // Process each file with secrets
    for (const location of scanResults.secretLocations) {
      try {
        // Read file content
        let content = await readFile(location.file, 'utf8');
        
        // Create backup
        const backupPath = path.join(this.backupDir, path.basename(location.file) + '.bak');
        await writeFile(backupPath, content);
        
        // Replace each secret
        for (const secret of location.secrets) {
          const vaultPath = `${this.mountPath}/${this.basePath}/${this.projectName}/${secret.vaultPath}`;
          const vaultReference = `{{vault:${vaultPath}:${secret.key}}}`;
          
          // Replace the secret with the vault reference
          content = content.replace(secret.match, secret.match.replace(secret.value, vaultReference));
        }
        
        // Write updated content
        await writeFile(location.file, content);
        console.log(`✅ Updated file with vault references: ${location.file}`);
      } catch (error) {
        console.error(`❌ Failed to update file ${location.file}: ${error.message}`);
      }
    }
    
    console.log('Secret replacement completed.');
  }

  /**
   * Main method to run the vault manager
   */
  async run(options) {
    const { scan, autoStore, replaceSecrets, projectDir } = options;
    const directory = projectDir || process.cwd();
    
    // Verify vault connection
    const connected = await this.verifyVaultConnection();
    if (!connected) {
      console.error('Aborting due to vault connection failure.');
      process.exit(1);
    }
    
    // Scan for secrets
    if (scan) {
      const scanResults = await this.scanForSecrets(directory);
      
      // Store secrets if requested
      if (autoStore && scanResults.secretsFound > 0) {
        await this.storeSecrets(scanResults);
        
        // Replace secrets with references if requested
        if (replaceSecrets) {
          await this.replaceSecretsWithReferences(scanResults);
        }
      }
      
      return scanResults;
    }
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  scan: args.includes('--scan'),
  autoStore: args.includes('--auto-store'),
  replaceSecrets: args.includes('--replace'),
  projectDir: args.includes('--project') ? args[args.indexOf('--project') + 1] : null
};

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

// Extract vault configuration and secret patterns
const vaultConfig = config.rules[0].vault_config;
const secretPatterns = config.rules[0].secret_patterns;

// Initialize and run the vault manager
const vaultManager = new VaultManager({
  backend: vaultConfig.backend,
  address: vaultConfig.address,
  tokenFile: vaultConfig.token_file,
  mountPath: vaultConfig.mount_path,
  basePath: vaultConfig.base_path,
  secretPatterns
});

vaultManager.run(options).catch(error => {
  console.error(`Error running vault manager: ${error.message}`);
  process.exit(1);
});

module.exports = VaultManager;
