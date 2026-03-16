/**
 * Secret rotation helpers.
 *
 * Provides rotation policy definitions, age checking for Vault secrets,
 * and batch checking utilities.
 */

import type { AgeReport } from "./models";
import { RotationError } from "./exceptions";
import type { VaultClient } from "./vault";

// ------------------------------------------------------------------
// Rotation Policy
// ------------------------------------------------------------------

export interface RotationPolicy {
  name: string;
  max_age_days: number;
  paths: string[];
  warn_age_days: number;
  auto_rotate: boolean;
  notify_channels: string[];
}

export function createRotationPolicy(
  name: string,
  opts: {
    max_age_days?: number;
    paths?: string[];
    warn_age_days?: number;
    auto_rotate?: boolean;
    notify_channels?: string[];
  } = {}
): RotationPolicy {
  const maxAge = opts.max_age_days ?? 90;
  return {
    name,
    max_age_days: maxAge,
    paths: opts.paths ?? [],
    warn_age_days: opts.warn_age_days ?? maxAge * 0.8,
    auto_rotate: opts.auto_rotate ?? false,
    notify_channels: opts.notify_channels ?? [],
  };
}

function globToRegex(pattern: string): RegExp {
  let regexStr = "^";
  for (const char of pattern) {
    if (char === "*") {
      regexStr += "[^/]*";
    } else if ("\\.+^${}()|[]".includes(char)) {
      regexStr += `\\${char}`;
    } else {
      regexStr += char;
    }
  }
  regexStr += "$";
  return new RegExp(regexStr);
}

export function policyMatchesPath(policy: RotationPolicy, secretPath: string): boolean {
  return policy.paths.some((pattern) => {
    const regex = globToRegex(pattern);
    return regex.test(secretPath);
  });
}

// ------------------------------------------------------------------
// Default Policies
// ------------------------------------------------------------------

export const DEFAULT_POLICIES: RotationPolicy[] = [
  createRotationPolicy("database-credentials", {
    max_age_days: 90,
    paths: ["kv/data/*/database/*", "kv/data/*/db/*"],
  }),
  createRotationPolicy("api-keys", {
    max_age_days: 180,
    paths: ["kv/data/*/api-keys/*", "kv/data/*/apikeys/*"],
  }),
  createRotationPolicy("service-accounts", {
    max_age_days: 365,
    paths: ["kv/data/*/service-accounts/*"],
  }),
  createRotationPolicy("tls-certificates", {
    max_age_days: 90,
    paths: ["kv/data/*/certs/*", "kv/data/*/tls/*"],
  }),
  createRotationPolicy("ssh-keys", {
    max_age_days: 90,
    paths: ["kv/data/*/ssh/*"],
  }),
];

// ------------------------------------------------------------------
// Age Checking
// ------------------------------------------------------------------

export async function checkSecretAge(
  vaultClient: VaultClient,
  secretPath: string,
  maxAgeDays: number = 90
): Promise<AgeReport> {
  try {
    const metadata = await vaultClient.kvMetadata(secretPath);

    let ageDays = 0;
    let created: Date | null = null;

    if (metadata.created_time) {
      try {
        created = new Date(metadata.created_time);
        if (isNaN(created.getTime())) {
          return {
            path: secretPath,
            current_version: metadata.version,
            created_time: null,
            age_days: 0,
            max_age_days: maxAgeDays,
            needs_rotation: false,
            detail: `Cannot parse created_time: ${metadata.created_time}`,
          };
        }
        ageDays = (Date.now() - created.getTime()) / (86400 * 1000);
      } catch {
        return {
          path: secretPath,
          current_version: metadata.version,
          created_time: null,
          age_days: 0,
          max_age_days: maxAgeDays,
          needs_rotation: false,
          detail: `Cannot parse created_time: ${metadata.created_time}`,
        };
      }
    }

    const needsRotation = ageDays > maxAgeDays;
    let detail: string;
    if (needsRotation) {
      const overdue = ageDays - maxAgeDays;
      detail = `Secret is ${overdue.toFixed(1)} days overdue for rotation`;
    } else if (ageDays > maxAgeDays * 0.8) {
      const remaining = maxAgeDays - ageDays;
      detail = `Secret will need rotation in ${remaining.toFixed(1)} days`;
    } else {
      detail = "Secret age is within policy";
    }

    return {
      path: secretPath,
      current_version: metadata.version,
      created_time: created?.toISOString() ?? null,
      age_days: ageDays,
      max_age_days: maxAgeDays,
      needs_rotation: needsRotation,
      detail,
    };
  } catch (err) {
    // VaultSecretNotFound
    if (err && typeof err === "object" && "name" in err && (err as { name: string }).name === "VaultSecretNotFound") {
      return {
        path: secretPath,
        current_version: 0,
        created_time: null,
        age_days: 0,
        max_age_days: maxAgeDays,
        needs_rotation: false,
        detail: `Secret not found at path: ${secretPath}`,
      };
    }
    // VaultConnectionError
    if (err && typeof err === "object" && "name" in err && (err as { name: string }).name === "VaultConnectionError") {
      throw new RotationError(`Cannot check age of ${secretPath}: ${err instanceof Error ? err.message : String(err)}`);
    }
    throw new RotationError(
      `Cannot check age of ${secretPath}: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

export async function checkSecretsBatch(
  vaultClient: VaultClient,
  paths: string[],
  policies?: RotationPolicy[]
): Promise<AgeReport[]> {
  const activePolicies = policies ?? DEFAULT_POLICIES;
  const reports: AgeReport[] = [];

  for (const secretPath of paths) {
    let maxAge = 90;
    for (const policy of activePolicies) {
      if (policyMatchesPath(policy, secretPath)) {
        maxAge = policy.max_age_days;
        break;
      }
    }

    try {
      const report = await checkSecretAge(vaultClient, secretPath, maxAge);
      reports.push(report);
    } catch (err) {
      reports.push({
        path: secretPath,
        current_version: 0,
        age_days: 0,
        max_age_days: maxAge,
        needs_rotation: false,
        detail: `Error: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  return reports;
}
