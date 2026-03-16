#!/usr/bin/env node
/**
 * Commander-based CLI for the secrets SDK.
 *
 * Entry point: `secrets-sdk`
 */

import { Command } from "commander";
import {
  validateRepoStructure,
  validateSopsYaml,
  validateVaultPolicy,
  scanPlaintextSecrets,
} from "./config";
import { VaultClient } from "./vault";
import { checkSecretAge } from "./rotation";
import { decryptFile } from "./sops";
import { healthReportOverallStatus, HealthStatus } from "./models";

const program = new Command();

program
  .name("secrets-sdk")
  .description("Developer identity and secrets management toolkit")
  .version("0.1.0");

// ------------------------------------------------------------------
// doctor
// ------------------------------------------------------------------

program
  .command("doctor")
  .description("Validate repository structure, .sops.yaml, and Vault policies")
  .option("--root <path>", "Repository root directory", ".")
  .option("--json-output", "Output results as JSON", false)
  .action((opts: { root: string; jsonOutput: boolean }) => {
    const issues = validateRepoStructure(opts.root);

    if (opts.jsonOutput) {
      console.log(JSON.stringify({ issues, count: issues.length }, null, 2));
    } else if (issues.length > 0) {
      console.error(`Found ${issues.length} issue(s):\n`);
      issues.forEach((issue, i) => {
        console.error(`  ${i + 1}. ${issue}`);
      });
      console.error();
      process.exit(1);
    } else {
      console.log("All checks passed.");
    }
  });

// ------------------------------------------------------------------
// vault-health
// ------------------------------------------------------------------

program
  .command("vault-health")
  .description("Check Vault connectivity and health status")
  .option("--addr <url>", "Vault address", process.env["VAULT_ADDR"] ?? "http://127.0.0.1:8200")
  .option("--json-output", "Output results as JSON", false)
  .action(async (opts: { addr: string; jsonOutput: boolean }) => {
    const client = new VaultClient({ addr: opts.addr });
    const report = await client.health();

    if (opts.jsonOutput) {
      const data = {
        overall: healthReportOverallStatus(report),
        checks: report.checks.map((c) => ({
          name: c.name,
          status: c.status,
          detail: c.detail,
          latency_ms: Math.round(c.latency_ms * 100) / 100,
        })),
      };
      console.log(JSON.stringify(data, null, 2));
    } else {
      const overall = healthReportOverallStatus(report);
      console.log(`[${overall.toUpperCase()}]`);
      console.log();
      for (const check of report.checks) {
        console.log(`  ${check.name}: ${check.status}`);
        if (check.detail) console.log(`    ${check.detail}`);
        if (check.latency_ms > 0) console.log(`    latency: ${check.latency_ms.toFixed(1)}ms`);
      }
      console.log();
      if (overall === HealthStatus.UNHEALTHY) {
        process.exit(1);
      }
    }
  });

// ------------------------------------------------------------------
// scan
// ------------------------------------------------------------------

program
  .command("scan <path>")
  .description("Scan files or directories for plaintext secrets")
  .option("--pattern <name...>", "Only check specific pattern names")
  .option("--json-output", "Output results as JSON", false)
  .action((scanPath: string, opts: { pattern?: string[]; jsonOutput: boolean }) => {
    const findings = scanPlaintextSecrets(scanPath, opts.pattern);

    if (opts.jsonOutput) {
      const data = findings.map((f) => ({
        file: f.file_path,
        line: f.line_number,
        pattern: f.pattern_name,
        match: f.matched_text,
        severity: f.severity,
      }));
      console.log(JSON.stringify(data, null, 2));
    } else if (findings.length > 0) {
      console.error(`Found ${findings.length} potential secret(s):\n`);
      for (const f of findings) {
        console.error(`  [${f.severity.toUpperCase()}] ${f.pattern_name}`);
        console.error(`    ${f.file_path}:${f.line_number}`);
        console.error(`    matched: ${f.matched_text}`);
        console.error();
      }
      process.exit(1);
    } else {
      console.log("No plaintext secrets found.");
    }
  });

// ------------------------------------------------------------------
// rotate-check
// ------------------------------------------------------------------

program
  .command("rotate-check")
  .description("Check secret ages against rotation policy")
  .option("--addr <url>", "Vault address", process.env["VAULT_ADDR"] ?? "http://127.0.0.1:8200")
  .requiredOption("--path <paths...>", "Secret path(s) to check")
  .option("--max-age <days>", "Maximum age in days", "90")
  .option("--json-output", "Output results as JSON", false)
  .action(async (opts: { addr: string; path: string[]; maxAge: string; jsonOutput: boolean }) => {
    const client = new VaultClient({ addr: opts.addr });
    const maxAge = parseFloat(opts.maxAge);
    const reports = [];

    for (const p of opts.path) {
      try {
        const report = await checkSecretAge(client, p, maxAge);
        reports.push(report);
      } catch (err) {
        console.error(`Error checking ${p}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (opts.jsonOutput) {
      const data = reports.map((r) => ({
        path: r.path,
        version: r.current_version,
        age_days: Math.round(r.age_days * 10) / 10,
        max_age_days: r.max_age_days,
        needs_rotation: r.needs_rotation,
        detail: r.detail,
      }));
      console.log(JSON.stringify(data, null, 2));
    } else {
      let anyOverdue = false;
      for (const r of reports) {
        const ageStr = `${r.age_days.toFixed(1)}d / ${r.max_age_days.toFixed(0)}d max`;
        if (r.needs_rotation) {
          anyOverdue = true;
          console.log(`  OVERDUE  ${r.path} (${ageStr})`);
        } else if (r.age_days > r.max_age_days * 0.8) {
          console.log(`  WARNING  ${r.path} (${ageStr})`);
        } else {
          console.log(`  OK       ${r.path} (${ageStr})`);
        }
        if (r.detail) console.log(`           ${r.detail}`);
      }
      if (anyOverdue) process.exit(1);
    }
  });

// ------------------------------------------------------------------
// decrypt
// ------------------------------------------------------------------

program
  .command("decrypt <file>")
  .description("Decrypt a SOPS-encrypted file and print the plaintext")
  .option("--output-format <format>", "Force output format (json, yaml)")
  .action((filePath: string, opts: { outputFormat?: string }) => {
    try {
      const data = decryptFile(filePath, opts.outputFormat);
      const fmt = opts.outputFormat || "json";
      if (fmt === "yaml") {
        const yaml = require("js-yaml");
        console.log(yaml.dump(data, { flowLevel: -1 }));
      } else {
        console.log(JSON.stringify(data, null, 2));
      }
    } catch (err) {
      console.error(`Decryption failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  });

// ------------------------------------------------------------------
// Parse and execute
// ------------------------------------------------------------------

program.parse();
