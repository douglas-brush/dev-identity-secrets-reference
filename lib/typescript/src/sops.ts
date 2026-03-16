/**
 * SOPS helpers for encrypting and decrypting secrets files.
 *
 * Wraps the `sops` CLI binary. Requires sops to be installed and on PATH.
 */

import { execFileSync, execFile } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as yaml from "js-yaml";

import {
  SopsDecryptError,
  SopsEncryptError,
  SopsNotInstalledError,
} from "./exceptions";

// ------------------------------------------------------------------
// Find sops binary
// ------------------------------------------------------------------

function findSops(): string {
  const { execSync } = require("child_process");
  try {
    const result = execSync("which sops", { encoding: "utf-8" }).trim();
    if (result) return result;
  } catch {
    // not found on unix
  }
  try {
    const result = execSync("where sops", { encoding: "utf-8" }).trim();
    if (result) return result.split("\n")[0]!.trim();
  } catch {
    // not found on windows
  }
  throw new SopsNotInstalledError();
}

function runSops(args: string[], env?: Record<string, string>): { stdout: string; stderr: string; exitCode: number } {
  const sops = findSops();
  const runEnv = { ...process.env, ...env };

  try {
    const stdout = execFileSync(sops, args, {
      encoding: "utf-8",
      env: runEnv as NodeJS.ProcessEnv,
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err: unknown) {
    const execErr = err as { stdout?: string; stderr?: string; status?: number };
    return {
      stdout: execErr.stdout ?? "",
      stderr: execErr.stderr ?? "",
      exitCode: execErr.status ?? 1,
    };
  }
}

// ------------------------------------------------------------------
// Format detection
// ------------------------------------------------------------------

export function detectFormat(filePath: string): string {
  const name = path.basename(filePath).toLowerCase();
  let suffix: string;

  if (name.includes(".enc.")) {
    suffix = name.split(".enc.").pop()!;
  } else {
    suffix = path.extname(filePath).replace(".", "");
  }

  if (suffix === "yaml" || suffix === "yml") return "yaml";
  if (suffix === "json") return "json";
  if (suffix === "env" || suffix === "dotenv") return "dotenv";
  return "json";
}

// ------------------------------------------------------------------
// Dotenv parser
// ------------------------------------------------------------------

export function parseDotenv(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (!line.includes("=")) continue;
    const eqIdx = line.indexOf("=");
    const key = line.slice(0, eqIdx).trim();
    let value = line.slice(eqIdx + 1).trim();
    if (
      value.length >= 2 &&
      value[0] === value[value.length - 1] &&
      (value[0] === '"' || value[0] === "'")
    ) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

// ------------------------------------------------------------------
// Decrypt
// ------------------------------------------------------------------

export function decryptFile(
  filePath: string,
  outputFormat: string = ""
): Record<string, unknown> {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const args = ["--decrypt"];
  if (outputFormat) {
    args.push("--output-type", outputFormat);
  }
  args.push(filePath);

  const result = runSops(args);
  if (result.exitCode !== 0) {
    throw new SopsDecryptError(filePath, result.stderr.trim());
  }

  const fmt = outputFormat || detectFormat(filePath);
  try {
    if (fmt === "json") {
      return JSON.parse(result.stdout) as Record<string, unknown>;
    } else if (fmt === "yaml" || fmt === "yml") {
      const loaded = yaml.load(result.stdout);
      if (typeof loaded === "object" && loaded !== null) {
        return loaded as Record<string, unknown>;
      }
      return { data: loaded };
    } else if (fmt === "dotenv") {
      return parseDotenv(result.stdout);
    } else {
      try {
        return JSON.parse(result.stdout) as Record<string, unknown>;
      } catch {
        const loaded = yaml.load(result.stdout);
        if (typeof loaded === "object" && loaded !== null) {
          return loaded as Record<string, unknown>;
        }
        return { data: loaded };
      }
    }
  } catch (err) {
    if (err instanceof SopsDecryptError) throw err;
    throw new SopsDecryptError(
      filePath,
      `Failed to parse decrypted output: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

// ------------------------------------------------------------------
// Encrypt
// ------------------------------------------------------------------

export function encryptFile(
  filePath: string,
  data: Record<string, unknown>,
  outputPath?: string,
  configPath?: string
): string {
  const out = outputPath ?? filePath;
  const fmt = detectFormat(filePath);

  // Write plaintext to temp file
  const tmpDir = os.tmpdir();
  const tmpFile = path.join(tmpDir, `sops-tmp-${Date.now()}.${fmt}`);

  try {
    if (fmt === "json") {
      fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2));
    } else if (fmt === "yaml" || fmt === "yml") {
      fs.writeFileSync(tmpFile, yaml.dump(data, { flowLevel: -1 }));
    } else if (fmt === "dotenv") {
      const lines = Object.entries(data).map(([k, v]) => `${k}=${v}`);
      fs.writeFileSync(tmpFile, lines.join("\n") + "\n");
    } else {
      fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2));
    }

    const args = ["--encrypt"];
    if (configPath) {
      args.push("--config", configPath);
    }
    if (fmt === "yaml" || fmt === "yml") {
      args.push("--input-type", "yaml", "--output-type", "yaml");
    } else if (fmt === "json") {
      args.push("--input-type", "json", "--output-type", "json");
    }
    args.push(tmpFile);

    const result = runSops(args);
    if (result.exitCode !== 0) {
      throw new SopsEncryptError(filePath, result.stderr.trim());
    }

    const outDir = path.dirname(out);
    if (!fs.existsSync(outDir)) {
      fs.mkdirSync(outDir, { recursive: true });
    }
    fs.writeFileSync(out, result.stdout);
    return out;
  } finally {
    try {
      fs.unlinkSync(tmpFile);
    } catch {
      // ignore cleanup errors
    }
  }
}

// ------------------------------------------------------------------
// SOPS Config Parser
// ------------------------------------------------------------------

export interface SopsCreationRule {
  path_regex: string;
  kms: string;
  azure_keyvault: string;
  gcp_kms: string;
  age: string;
  pgp: string;
  encrypted_regex: string;
}

export interface SopsConfig {
  path: string;
  creation_rules: SopsCreationRule[];
}

export function parseSopsConfig(filePath: string): SopsConfig {
  if (!fs.existsSync(filePath)) {
    throw new Error(`.sops.yaml not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const raw = yaml.load(content);

  if (typeof raw !== "object" || raw === null) {
    throw new Error(
      `Invalid .sops.yaml: expected a YAML mapping, got ${typeof raw}`
    );
  }

  const doc = raw as Record<string, unknown>;
  const rulesRaw = doc["creation_rules"];

  if (!Array.isArray(rulesRaw)) {
    return { path: filePath, creation_rules: [] };
  }

  const rules: SopsCreationRule[] = rulesRaw
    .filter((entry): entry is Record<string, unknown> => typeof entry === "object" && entry !== null)
    .map((entry) => ({
      path_regex: String(entry["path_regex"] ?? ""),
      kms: String(entry["kms"] ?? ""),
      azure_keyvault: String(entry["azure_keyvault"] ?? ""),
      gcp_kms: String(entry["gcp_kms"] ?? ""),
      age: String(entry["age"] ?? ""),
      pgp: String(entry["pgp"] ?? ""),
      encrypted_regex: String(entry["encrypted_regex"] ?? ""),
    }));

  return { path: filePath, creation_rules: rules };
}

export function sopsConfigHasCloudKms(
  config: SopsConfig,
  ruleIndex?: number
): boolean {
  const targets =
    ruleIndex !== undefined
      ? [config.creation_rules[ruleIndex]!]
      : config.creation_rules;
  return targets.some(
    (r) => Boolean(r.kms) || Boolean(r.azure_keyvault) || Boolean(r.gcp_kms)
  );
}

export function sopsConfigRulesForPath(
  config: SopsConfig,
  filePath: string
): SopsCreationRule[] {
  const matches: SopsCreationRule[] = [];
  for (const rule of config.creation_rules) {
    if (rule.path_regex) {
      try {
        if (new RegExp(rule.path_regex).test(filePath)) {
          matches.push(rule);
        }
      } catch {
        // invalid regex, skip
      }
    }
  }
  return matches;
}
