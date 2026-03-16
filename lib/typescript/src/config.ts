/**
 * Configuration validation for repository structure, SOPS config, and Vault policies.
 *
 * Validates that a dev-identity-secrets-reference repository is correctly
 * structured, that .sops.yaml follows best practices, that Vault HCL policies
 * parse correctly, and that no plaintext secrets are checked in.
 */

import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";

import type { SecretFinding } from "./models";

// ------------------------------------------------------------------
// .sops.yaml Validation
// ------------------------------------------------------------------

export function validateSopsYaml(filePath: string): string[] {
  const issues: string[] = [];

  if (!fs.existsSync(filePath)) {
    issues.push(`File not found: ${filePath}`);
    return issues;
  }

  let raw: unknown;
  try {
    raw = yaml.load(fs.readFileSync(filePath, "utf-8"));
  } catch (err) {
    issues.push(`Invalid YAML: ${err instanceof Error ? err.message : String(err)}`);
    return issues;
  }

  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    issues.push("Root must be a YAML mapping");
    return issues;
  }

  const doc = raw as Record<string, unknown>;
  const rules = doc["creation_rules"];

  if (rules === undefined) {
    issues.push("Missing 'creation_rules' key");
    return issues;
  }

  if (!Array.isArray(rules)) {
    issues.push("'creation_rules' must be a list");
    return issues;
  }

  if (rules.length === 0) {
    issues.push("'creation_rules' is empty -- no encryption rules defined");
    return issues;
  }

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    const prefix = `Rule ${i}`;

    if (typeof rule !== "object" || rule === null) {
      issues.push(`${prefix}: must be a mapping`);
      continue;
    }

    const ruleObj = rule as Record<string, unknown>;
    const pathRegex = String(ruleObj["path_regex"] ?? "");

    if (!pathRegex) {
      issues.push(`${prefix}: missing 'path_regex'`);
    } else {
      try {
        new RegExp(pathRegex);
      } catch (err) {
        issues.push(
          `${prefix}: invalid regex '${pathRegex}': ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Key sources
    const keySources = ["kms", "azure_keyvault", "gcp_kms", "age", "pgp", "hc_vault_transit_uri"];
    const hasKey = keySources.some((k) => Boolean(ruleObj[k]));
    if (!hasKey) {
      issues.push(
        `${prefix}: no encryption key source (kms, age, gcp_kms, azure_keyvault, pgp)`
      );
    }

    // Production should use cloud KMS
    if (pathRegex && pathRegex.toLowerCase().includes("prod")) {
      const hasCloud = ["kms", "azure_keyvault", "gcp_kms"].some((k) =>
        Boolean(ruleObj[k])
      );
      if (!hasCloud) {
        issues.push(
          `${prefix}: production rule '${pathRegex}' should use cloud KMS, not age-only`
        );
      }
    }

    // encrypted_regex check
    const encRegex = String(ruleObj["encrypted_regex"] ?? "");
    if (!encRegex) {
      issues.push(
        `${prefix}: missing 'encrypted_regex' -- all fields will be encrypted`
      );
    } else {
      try {
        new RegExp(encRegex);
      } catch (err) {
        issues.push(
          `${prefix}: invalid encrypted_regex: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }
  }

  return issues;
}

// ------------------------------------------------------------------
// Vault HCL Policy Validation
// ------------------------------------------------------------------

const PATH_BLOCK_RE = /path\s+"([^"]+)"\s*\{([^}]*)\}/gs;
const CAPABILITIES_RE = /capabilities\s*=\s*\[([^\]]*)\]/;

const VALID_CAPABILITIES = new Set([
  "create", "read", "update", "delete", "list", "sudo", "deny", "patch",
]);

const DANGEROUS_CAPABILITIES = new Set(["sudo", "delete"]);

export function validateVaultPolicy(filePath: string): string[] {
  const issues: string[] = [];

  if (!fs.existsSync(filePath)) {
    issues.push(`File not found: ${filePath}`);
    return issues;
  }

  const content = fs.readFileSync(filePath, "utf-8");
  if (!content.trim()) {
    issues.push("Policy file is empty");
    return issues;
  }

  const blocks: Array<[string, string]> = [];
  let match: RegExpExecArray | null;
  const re = new RegExp(PATH_BLOCK_RE.source, PATH_BLOCK_RE.flags);
  while ((match = re.exec(content)) !== null) {
    blocks.push([match[1]!, match[2]!]);
  }

  if (blocks.length === 0) {
    issues.push("No 'path' blocks found -- is this a valid Vault policy?");
    return issues;
  }

  for (const [vaultPath, blockBody] of blocks) {
    const prefix = `path "${vaultPath}"`;

    const capMatch = CAPABILITIES_RE.exec(blockBody);
    if (!capMatch) {
      issues.push(`${prefix}: missing 'capabilities' list`);
      continue;
    }

    const rawCaps = capMatch[1]!;
    const caps = rawCaps
      .split(",")
      .map((c) => c.trim().replace(/['"]/g, ""))
      .filter(Boolean);

    for (const cap of caps) {
      if (!VALID_CAPABILITIES.has(cap)) {
        issues.push(`${prefix}: unknown capability '${cap}'`);
      }
      if (DANGEROUS_CAPABILITIES.has(cap)) {
        issues.push(
          `${prefix}: uses dangerous capability '${cap}' -- ensure this is intentional`
        );
      }
    }

    // Warn on broad paths
    if (vaultPath.endsWith("*") && !vaultPath.endsWith("/*")) {
      issues.push(
        `${prefix}: very broad path pattern -- consider narrowing scope`
      );
    }

    // Warn on root-level access
    if (["*", "sys/*", "auth/*"].includes(vaultPath)) {
      issues.push(
        `${prefix}: root-level access -- this should only be in emergency/admin policies`
      );
    }
  }

  return issues;
}

// ------------------------------------------------------------------
// Repository Structure Validation
// ------------------------------------------------------------------

const EXPECTED_DIRS = [
  "platform/vault/policies",
  "secrets",
  "docs",
];

const EXPECTED_FILES = [".sops.yaml"];

export function validateRepoStructure(root: string): string[] {
  const issues: string[] = [];

  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    issues.push(`Repository root not found or not a directory: ${root}`);
    return issues;
  }

  // Check expected directories
  for (const d of EXPECTED_DIRS) {
    const dirPath = path.join(root, d);
    if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) {
      issues.push(`Missing expected directory: ${d}`);
    }
  }

  // Check expected files
  for (const f of EXPECTED_FILES) {
    if (!fs.existsSync(path.join(root, f))) {
      issues.push(`Missing expected file: ${f}`);
    }
  }

  // Validate .sops.yaml if it exists
  const sopsPath = path.join(root, ".sops.yaml");
  if (fs.existsSync(sopsPath)) {
    const sopsIssues = validateSopsYaml(sopsPath);
    for (const issue of sopsIssues) {
      issues.push(`.sops.yaml: ${issue}`);
    }
  }

  // Validate Vault policies
  const policyDir = path.join(root, "platform", "vault", "policies");
  if (fs.existsSync(policyDir) && fs.statSync(policyDir).isDirectory()) {
    const hclFiles = fs
      .readdirSync(policyDir)
      .filter((f) => f.endsWith(".hcl"))
      .sort();
    for (const hclFile of hclFiles) {
      const fullPath = path.join(policyDir, hclFile);
      const policyIssues = validateVaultPolicy(fullPath);
      for (const issue of policyIssues) {
        const rel = path.relative(root, fullPath);
        issues.push(`${rel}: ${issue}`);
      }
    }
  }

  // Check secrets directory structure
  const secretsDir = path.join(root, "secrets");
  if (fs.existsSync(secretsDir) && fs.statSync(secretsDir).isDirectory()) {
    const expectedEnvs = new Set(["dev", "staging", "prod"]);
    const actualEnvs = new Set(
      fs
        .readdirSync(secretsDir)
        .filter((d) => fs.statSync(path.join(secretsDir, d)).isDirectory())
    );
    for (const env of [...expectedEnvs].sort()) {
      if (!actualEnvs.has(env)) {
        issues.push(`Missing secrets environment directory: secrets/${env}`);
      }
    }

    // Check for unencrypted files
    walkDir(secretsDir, (filePath) => {
      const name = path.basename(filePath);
      const safeNames = new Set([".gitkeep", ".gitignore", "README.md", "README"]);
      const safeExtensions = [".enc.yaml", ".enc.yml", ".enc.json", ".enc.env"];
      const isSafe =
        safeNames.has(name) ||
        safeExtensions.some((ext) => name.endsWith(ext)) ||
        name.startsWith(".");
      if (!isSafe) {
        const rel = path.relative(root, filePath);
        issues.push(
          `Potentially unencrypted file in secrets/: ${rel} (expected .enc.yaml/.enc.json or metadata files)`
        );
      }
    });
  }

  return issues;
}

// ------------------------------------------------------------------
// Plaintext Secret Scanning
// ------------------------------------------------------------------

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "AWS Access Key",
    regex: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/,
    severity: "high",
  },
  {
    name: "AWS Secret Key",
    regex: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/i,
    severity: "high",
  },
  {
    name: "Generic API Key Assignment",
    regex: /(?:api_key|apikey|api_secret)\s*[=:]\s*['"][A-Za-z0-9_\-]{20,}['"]/i,
    severity: "high",
  },
  {
    name: "Generic Password Assignment",
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/i,
    severity: "medium",
  },
  {
    name: "Generic Token Assignment",
    regex: /(?:token|bearer|auth_token)\s*[=:]\s*['"][A-Za-z0-9_\-.]{20,}['"]/i,
    severity: "medium",
  },
  {
    name: "Private Key Block",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "GitHub Token",
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
    severity: "high",
  },
  {
    name: "Slack Token",
    regex: /xox[baprs]-[0-9]{10,13}-[A-Za-z0-9-]{20,}/,
    severity: "high",
  },
  {
    name: "Vault Token",
    regex: /(?:hvs|s)\.[A-Za-z0-9]{24,}/,
    severity: "high",
  },
  {
    name: "Connection String with Password",
    regex: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@/i,
    severity: "high",
  },
];

const SCANNABLE_EXTENSIONS = new Set([
  ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php",
  ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
  ".env", ".sh", ".bash", ".zsh", ".ps1", ".tf", ".hcl",
  ".xml", ".properties", ".gradle",
]);

const SKIP_DIRS = new Set([
  ".git", "__pycache__", "node_modules", ".venv", "venv",
  ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
  ".eggs",
]);

const MAX_SCAN_SIZE = 1_048_576;

export function scanPlaintextSecrets(
  scanPath: string,
  includePatterns?: string[],
  excludeDirs?: Set<string>
): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const skip = new Set([...SKIP_DIRS, ...(excludeDirs ?? [])]);

  let patterns = SECRET_PATTERNS;
  if (includePatterns) {
    const nameSet = new Set(includePatterns);
    patterns = SECRET_PATTERNS.filter((p) => nameSet.has(p.name));
  }

  const stat = fs.statSync(scanPath);
  if (stat.isFile()) {
    findings.push(...scanFile(scanPath, patterns));
  } else if (stat.isDirectory()) {
    walkDir(
      scanPath,
      (filePath) => {
        const ext = path.extname(filePath).toLowerCase();
        if (SCANNABLE_EXTENSIONS.has(ext)) {
          findings.push(...scanFile(filePath, patterns));
        }
      },
      skip
    );
  }

  return findings;
}

function scanFile(filePath: string, patterns: SecretPattern[]): SecretFinding[] {
  const findings: SecretFinding[] = [];

  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_SCAN_SIZE || stat.size === 0) return findings;
    const content = fs.readFileSync(filePath, "utf-8");

    const lines = content.split("\n");
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum]!;
      for (const pattern of patterns) {
        const match = pattern.regex.exec(line);
        if (match) {
          const raw = match[0];
          let redacted: string;
          if (raw.length > 12) {
            redacted = raw.slice(0, 4) + "..." + raw.slice(-4);
          } else {
            redacted = raw.slice(0, 4) + "...";
          }
          findings.push({
            file_path: filePath,
            line_number: lineNum + 1,
            pattern_name: pattern.name,
            matched_text: redacted,
            severity: pattern.severity,
          });
        }
      }
    }
  } catch {
    // skip files that can't be read
  }

  return findings;
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function walkDir(
  dir: string,
  callback: (filePath: string) => void,
  skipDirs?: Set<string>
): void {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (skipDirs?.has(entry.name)) continue;
      if (entry.name.endsWith(".egg-info")) continue;
      walkDir(fullPath, callback, skipDirs);
    } else if (entry.isFile()) {
      callback(fullPath);
    }
  }
}
