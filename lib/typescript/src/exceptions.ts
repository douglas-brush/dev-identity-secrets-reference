/**
 * Custom error classes for the secrets SDK.
 *
 * Mirrors the Python SDK exception hierarchy.
 */

export class SecretsSDKError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecretsSDKError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class VaultError extends SecretsSDKError {
  constructor(message: string) {
    super(message);
    this.name = "VaultError";
  }
}

export class VaultAuthError extends VaultError {
  public readonly method: string;
  public readonly detail: string;

  constructor(method: string, detail: string = "") {
    const msg = detail
      ? `Vault authentication failed using ${method}: ${detail}`
      : `Vault authentication failed using ${method}`;
    super(msg);
    this.name = "VaultAuthError";
    this.method = method;
    this.detail = detail;
  }
}

export class VaultSecretNotFound extends VaultError {
  public readonly path: string;

  constructor(path: string) {
    super(`Secret not found at path: ${path}`);
    this.name = "VaultSecretNotFound";
    this.path = path;
  }
}

export class VaultConnectionError extends VaultError {
  public readonly addr: string;
  public readonly detail: string;

  constructor(addr: string, detail: string = "") {
    const msg = detail
      ? `Cannot connect to Vault at ${addr}: ${detail}`
      : `Cannot connect to Vault at ${addr}`;
    super(msg);
    this.name = "VaultConnectionError";
    this.addr = addr;
    this.detail = detail;
  }
}

export class VaultLeaseError extends VaultError {
  public readonly leaseId: string;
  public readonly operation: string;
  public readonly detail: string;

  constructor(leaseId: string, operation: string, detail: string = "") {
    const msg = detail
      ? `Lease ${operation} failed for ${leaseId}: ${detail}`
      : `Lease ${operation} failed for ${leaseId}`;
    super(msg);
    this.name = "VaultLeaseError";
    this.leaseId = leaseId;
    this.operation = operation;
    this.detail = detail;
  }
}

export class SopsError extends SecretsSDKError {
  constructor(message: string) {
    super(message);
    this.name = "SopsError";
  }
}

export class SopsDecryptError extends SopsError {
  public readonly path: string;
  public readonly detail: string;

  constructor(path: string, detail: string = "") {
    const msg = detail
      ? `SOPS decryption failed for ${path}: ${detail}`
      : `SOPS decryption failed for ${path}`;
    super(msg);
    this.name = "SopsDecryptError";
    this.path = path;
    this.detail = detail;
  }
}

export class SopsEncryptError extends SopsError {
  public readonly path: string;
  public readonly detail: string;

  constructor(path: string, detail: string = "") {
    const msg = detail
      ? `SOPS encryption failed for ${path}: ${detail}`
      : `SOPS encryption failed for ${path}`;
    super(msg);
    this.name = "SopsEncryptError";
    this.path = path;
    this.detail = detail;
  }
}

export class SopsNotInstalledError extends SopsError {
  constructor() {
    super(
      "sops binary not found on PATH. Install from https://github.com/getsops/sops"
    );
    this.name = "SopsNotInstalledError";
  }
}

export class ConfigValidationError extends SecretsSDKError {
  public readonly issues: string[];

  constructor(issues: string[]) {
    const count = issues.length;
    const summary = `Configuration validation found ${count} issue${count !== 1 ? "s" : ""}`;
    const detail = issues.map((i) => `  - ${i}`).join("\n");
    super(`${summary}:\n${detail}`);
    this.name = "ConfigValidationError";
    this.issues = issues;
  }
}

export class RotationError extends SecretsSDKError {
  public readonly detail: string;

  constructor(detail: string) {
    super(`Secret rotation failed: ${detail}`);
    this.name = "RotationError";
    this.detail = detail;
  }
}
