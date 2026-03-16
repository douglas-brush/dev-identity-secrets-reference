/**
 * Unit tests for configuration validation.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import {
  validateSopsYaml,
  validateVaultPolicy,
  validateRepoStructure,
  scanPlaintextSecrets,
} from "../src/config";

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function createTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "config-test-"));
}

function createSampleRepo(tmpDir: string): string {
  // Create expected dirs
  fs.mkdirSync(path.join(tmpDir, "platform", "vault", "policies"), { recursive: true });
  fs.mkdirSync(path.join(tmpDir, "secrets", "dev"), { recursive: true });
  fs.mkdirSync(path.join(tmpDir, "secrets", "staging"), { recursive: true });
  fs.mkdirSync(path.join(tmpDir, "secrets", "prod"), { recursive: true });
  fs.mkdirSync(path.join(tmpDir, "docs"), { recursive: true });

  // .sops.yaml
  fs.writeFileSync(
    path.join(tmpDir, ".sops.yaml"),
    [
      "creation_rules:",
      "  - path_regex: secrets/dev/.*\\.enc\\.yaml$",
      "    age: 'age1abc'",
      "    encrypted_regex: '^(password|token)$'",
      "  - path_regex: secrets/prod/.*\\.enc\\.yaml$",
      "    age: 'age1prod'",
      "    encrypted_regex: '^(password|token)$'",
    ].join("\n")
  );

  // Vault policy
  fs.writeFileSync(
    path.join(tmpDir, "platform", "vault", "policies", "dev-read.hcl"),
    'path "kv/data/dev/*" {\n  capabilities = ["read", "list"]\n}\n'
  );

  // Encrypted file
  fs.writeFileSync(
    path.join(tmpDir, "secrets", "dev", "app.enc.yaml"),
    "password: ENC[AES256_GCM,data:xxx]\n"
  );

  return tmpDir;
}

// ------------------------------------------------------------------
// validateSopsYaml
// ------------------------------------------------------------------

describe("validateSopsYaml", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("valid config (prod KMS warning expected)", () => {
    const repo = createSampleRepo(tmpDir);
    const issues = validateSopsYaml(path.join(repo, ".sops.yaml"));
    const prodIssues = issues.filter((i) => i.includes("cloud KMS"));
    expect(prodIssues.length).toBe(1);
  });

  test("missing file", () => {
    const issues = validateSopsYaml("/nonexistent/.sops.yaml");
    expect(issues.some((i) => i.toLowerCase().includes("not found"))).toBe(true);
  });

  test("empty rules", () => {
    const f = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(f, "creation_rules: []\n");
    const issues = validateSopsYaml(f);
    expect(issues.some((i) => i.toLowerCase().includes("empty"))).toBe(true);
  });

  test("missing path_regex", () => {
    const f = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(
      f,
      ["creation_rules:", "  - age: 'age1abc'", "    encrypted_regex: '^(password)$'"].join("\n")
    );
    const issues = validateSopsYaml(f);
    expect(issues.some((i) => i.includes("path_regex"))).toBe(true);
  });

  test("invalid regex", () => {
    const f = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(
      f,
      ["creation_rules:", "  - path_regex: '[invalid'", "    age: 'age1abc'"].join("\n")
    );
    const issues = validateSopsYaml(f);
    expect(issues.some((i) => i.toLowerCase().includes("invalid regex"))).toBe(true);
  });

  test("no key source", () => {
    const f = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(
      f,
      [
        "creation_rules:",
        "  - path_regex: secrets/dev/.*",
        "    encrypted_regex: '^(password)$'",
      ].join("\n")
    );
    const issues = validateSopsYaml(f);
    expect(issues.some((i) => i.toLowerCase().includes("no encryption key"))).toBe(true);
  });

  test("invalid yaml", () => {
    const f = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(f, "{{invalid yaml");
    const issues = validateSopsYaml(f);
    expect(issues.length).toBeGreaterThan(0);
  });

  test("prod cloud KMS warning", () => {
    const f = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(
      f,
      [
        "creation_rules:",
        "  - path_regex: secrets/prod/.*\\.enc\\.yaml$",
        "    age: 'age1onlyage'",
        "    encrypted_regex: '^(password)$'",
      ].join("\n")
    );
    const issues = validateSopsYaml(f);
    expect(issues.some((i) => i.includes("cloud KMS"))).toBe(true);
  });

  test("no encrypted_regex warning", () => {
    const f = path.join(tmpDir, ".sops.yaml");
    fs.writeFileSync(
      f,
      ["creation_rules:", "  - path_regex: secrets/dev/.*", "    age: 'age1abc'"].join("\n")
    );
    const issues = validateSopsYaml(f);
    expect(issues.some((i) => i.includes("encrypted_regex"))).toBe(true);
  });
});

// ------------------------------------------------------------------
// validateVaultPolicy
// ------------------------------------------------------------------

describe("validateVaultPolicy", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("valid policy", () => {
    const f = path.join(tmpDir, "dev-read.hcl");
    fs.writeFileSync(
      f,
      'path "kv/data/dev/*" {\n  capabilities = ["read", "list"]\n}\n'
    );
    const issues = validateVaultPolicy(f);
    expect(issues).toEqual([]);
  });

  test("missing file", () => {
    const issues = validateVaultPolicy("/nonexistent.hcl");
    expect(issues.some((i) => i.toLowerCase().includes("not found"))).toBe(true);
  });

  test("empty file", () => {
    const f = path.join(tmpDir, "empty.hcl");
    fs.writeFileSync(f, "");
    const issues = validateVaultPolicy(f);
    expect(issues.some((i) => i.toLowerCase().includes("empty"))).toBe(true);
  });

  test("no path blocks", () => {
    const f = path.join(tmpDir, "nopath.hcl");
    fs.writeFileSync(f, "# Just a comment\n");
    const issues = validateVaultPolicy(f);
    expect(issues.some((i) => i.includes("No 'path' blocks"))).toBe(true);
  });

  test("unknown capability", () => {
    const f = path.join(tmpDir, "bad-cap.hcl");
    fs.writeFileSync(
      f,
      'path "kv/data/*" {\n  capabilities = ["read", "execute"]\n}\n'
    );
    const issues = validateVaultPolicy(f);
    expect(issues.some((i) => i.includes("unknown capability"))).toBe(true);
  });

  test("dangerous capability warning", () => {
    const f = path.join(tmpDir, "admin.hcl");
    fs.writeFileSync(
      f,
      'path "sys/policy/*" {\n  capabilities = ["create", "read", "update", "delete", "sudo"]\n}\n'
    );
    const issues = validateVaultPolicy(f);
    const dangerous = issues.filter((i) => i.toLowerCase().includes("dangerous"));
    expect(dangerous.length).toBe(2); // delete + sudo
  });

  test("missing capabilities", () => {
    const f = path.join(tmpDir, "nocap.hcl");
    fs.writeFileSync(
      f,
      'path "kv/data/*" {\n  # no capabilities\n}\n'
    );
    const issues = validateVaultPolicy(f);
    expect(
      issues.some(
        (i) => i.toLowerCase().includes("missing") && i.toLowerCase().includes("capabilities")
      )
    ).toBe(true);
  });

  test("broad path warning", () => {
    const f = path.join(tmpDir, "broad.hcl");
    fs.writeFileSync(
      f,
      'path "sys/*" {\n  capabilities = ["read"]\n}\n'
    );
    const issues = validateVaultPolicy(f);
    expect(issues.some((i) => i.includes("root-level"))).toBe(true);
  });
});

// ------------------------------------------------------------------
// validateRepoStructure
// ------------------------------------------------------------------

describe("validateRepoStructure", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("valid structure", () => {
    const repo = createSampleRepo(tmpDir);
    const issues = validateRepoStructure(repo);
    // Only expect prod KMS warning
    const nonKms = issues.filter((i) => !i.includes("cloud KMS"));
    expect(nonKms).toEqual([]);
  });

  test("missing dirs", () => {
    fs.writeFileSync(path.join(tmpDir, ".sops.yaml"), "creation_rules: []\n");
    const issues = validateRepoStructure(tmpDir);
    expect(issues.some((i) => i.includes("platform/vault/policies"))).toBe(true);
    expect(issues.some((i) => i.includes("secrets"))).toBe(true);
  });

  test("unencrypted file warning", () => {
    const repo = createSampleRepo(tmpDir);
    fs.writeFileSync(
      path.join(repo, "secrets", "dev", "plaintext.yaml"),
      "password: bad\n"
    );
    const issues = validateRepoStructure(repo);
    expect(
      issues.some((i) => i.toLowerCase().includes("unencrypted") || i.includes("Potentially"))
    ).toBe(true);
  });

  test("nonexistent root", () => {
    const issues = validateRepoStructure("/nonexistent/repo");
    expect(issues.some((i) => i.toLowerCase().includes("not found"))).toBe(true);
  });
});

// ------------------------------------------------------------------
// scanPlaintextSecrets
// ------------------------------------------------------------------

describe("scanPlaintextSecrets", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = createTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("detect AWS key", () => {
    const f = path.join(tmpDir, "config.py");
    fs.writeFileSync(f, 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n');
    const findings = scanPlaintextSecrets(tmpDir);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some((f) => f.pattern_name === "AWS Access Key")).toBe(true);
  });

  test("detect private key", () => {
    const f = path.join(tmpDir, "key.py");
    fs.writeFileSync(
      f,
      'key = """-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----"""\n'
    );
    const findings = scanPlaintextSecrets(tmpDir);
    expect(findings.some((f) => f.pattern_name === "Private Key Block")).toBe(true);
  });

  test("detect GitHub token", () => {
    const f = path.join(tmpDir, "ci.yaml");
    fs.writeFileSync(f, "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n");
    const findings = scanPlaintextSecrets(tmpDir);
    expect(findings.some((f) => f.pattern_name === "GitHub Token")).toBe(true);
  });

  test("detect connection string", () => {
    const f = path.join(tmpDir, "db.py");
    fs.writeFileSync(f, 'DSN = "postgres://user:password@host:5432/db"\n');
    const findings = scanPlaintextSecrets(tmpDir);
    expect(
      findings.some((f) => f.pattern_name === "Connection String with Password")
    ).toBe(true);
  });

  test("clean file", () => {
    const f = path.join(tmpDir, "clean.py");
    fs.writeFileSync(f, 'x = 42\nname = "hello"\n');
    const findings = scanPlaintextSecrets(tmpDir);
    expect(findings).toEqual([]);
  });

  test("skip binary extensions", () => {
    const f = path.join(tmpDir, "image.png");
    fs.writeFileSync(f, Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]), Buffer.from("AKIAIOSFODNN7EXAMPLE")]));
    const findings = scanPlaintextSecrets(tmpDir);
    expect(findings).toEqual([]);
  });

  test("respects include patterns", () => {
    const f = path.join(tmpDir, "mixed.py");
    fs.writeFileSync(
      f,
      'key = "AKIAIOSFODNN7EXAMPLE"\ndsn = "postgres://u:p@h:5432/db"\n'
    );
    const findings = scanPlaintextSecrets(tmpDir, ["AWS Access Key"]);
    expect(findings.every((f) => f.pattern_name === "AWS Access Key")).toBe(true);
  });

  test("redacts matched text", () => {
    const f = path.join(tmpDir, "key.py");
    fs.writeFileSync(f, 'key = "AKIAIOSFODNN7EXAMPLE"\n');
    const findings = scanPlaintextSecrets(tmpDir);
    for (const finding of findings) {
      expect(finding.matched_text).toContain("...");
    }
  });

  test("single file scan", () => {
    const f = path.join(tmpDir, "single.py");
    fs.writeFileSync(f, 'key = "AKIAIOSFODNN7EXAMPLE"\n');
    const findings = scanPlaintextSecrets(f);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});
