/**
 * Vault client wrapper providing typed access to HashiCorp Vault operations.
 *
 * Supports token, AppRole, and OIDC authentication. All operations handle
 * missing connectivity gracefully by raising clear exceptions.
 */

import {
  VaultAuthError,
  VaultConnectionError,
  VaultLeaseError,
  VaultSecretNotFound,
} from "./exceptions";
import {
  AuditEvent,
  AuditEventType,
  CertInfo,
  HealthCheck,
  HealthReport,
  HealthStatus,
  LeaseInfo,
  SSHCertInfo,
  SecretMetadata,
  TransitResult,
  createAuditEvent,
  healthReportOverallStatus,
  healthReportSummary,
} from "./models";

// Type for the node-vault client
export interface VaultBackend {
  read(path: string): Promise<Record<string, unknown>>;
  write(path: string, data: Record<string, unknown>): Promise<Record<string, unknown>>;
  delete(path: string): Promise<void>;
  list(path: string): Promise<Record<string, unknown>>;
  health(opts?: Record<string, unknown>): Promise<Record<string, unknown>>;
  tokenLookupSelf(): Promise<Record<string, unknown>>;
  tokenRenewSelf(opts?: Record<string, unknown>): Promise<Record<string, unknown>>;
  tokenRevokeSelf(): Promise<void>;
}

export interface VaultClientOptions {
  addr?: string;
  token?: string;
  namespace?: string;
  verify?: boolean;
  kvMount?: string;
  backend?: VaultBackend;
}

export class VaultClient {
  private readonly _addr: string;
  private readonly _namespace: string | undefined;
  private readonly _kvMount: string;
  private readonly _verify: boolean;
  private readonly _auditEvents: AuditEvent[] = [];
  private _backend: VaultBackend;
  private _token: string | undefined;
  private _renewalTimer: ReturnType<typeof setInterval> | null = null;

  constructor(opts: VaultClientOptions = {}) {
    this._addr = opts.addr ?? process.env["VAULT_ADDR"] ?? "http://127.0.0.1:8200";
    this._namespace = opts.namespace ?? process.env["VAULT_NAMESPACE"];
    this._kvMount = opts.kvMount ?? "kv";
    this._token = opts.token ?? process.env["VAULT_TOKEN"];

    if (opts.verify !== undefined) {
      this._verify = opts.verify;
    } else {
      const skip = (process.env["VAULT_SKIP_VERIFY"] ?? "").toLowerCase();
      this._verify = !["1", "true"].includes(skip);
    }

    if (opts.backend) {
      this._backend = opts.backend;
    } else {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const vault = require("node-vault");
      this._backend = vault({
        apiVersion: "v1",
        endpoint: this._addr,
        token: this._token,
        namespace: this._namespace,
      }) as VaultBackend;
    }
  }

  // ------------------------------------------------------------------
  // Properties
  // ------------------------------------------------------------------

  get addr(): string {
    return this._addr;
  }

  get backend(): VaultBackend {
    return this._backend;
  }

  get auditLog(): AuditEvent[] {
    return [...this._auditEvents];
  }

  // ------------------------------------------------------------------
  // Authentication
  // ------------------------------------------------------------------

  async authToken(token?: string): Promise<void> {
    const t = token ?? process.env["VAULT_TOKEN"];
    if (!t) {
      throw new VaultAuthError("token", "No token provided and VAULT_TOKEN not set");
    }
    this._token = t;

    try {
      const result = await this._backend.tokenLookupSelf();
      if (!result) {
        throw new VaultAuthError("token", "Token lookup returned null");
      }
      this._emit(AuditEventType.AUTH_SUCCESS, { detail: "method=token" });
    } catch (err) {
      if (err instanceof VaultAuthError) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("403") || msg.includes("permission denied")) {
        this._emit(AuditEventType.AUTH_FAILURE, { detail: "method=token", success: false });
        throw new VaultAuthError("token", "Token is invalid or expired");
      }
      this._emit(AuditEventType.AUTH_FAILURE, { detail: "method=token", success: false });
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  async authAppRole(
    roleId?: string,
    secretId?: string,
    mountPoint: string = "approle"
  ): Promise<void> {
    const rid = roleId ?? process.env["VAULT_ROLE_ID"] ?? "";
    const sid = secretId ?? process.env["VAULT_SECRET_ID"] ?? "";

    if (!rid) {
      throw new VaultAuthError("approle", "No role_id provided and VAULT_ROLE_ID not set");
    }

    try {
      const result = await this._backend.write(`auth/${mountPoint}/login`, {
        role_id: rid,
        secret_id: sid,
      });
      const auth = result?.["auth"] as Record<string, unknown> | undefined;
      this._token = auth?.["client_token"] as string;
      this._emit(AuditEventType.AUTH_SUCCESS, { detail: "method=approle" });
    } catch (err) {
      if (err instanceof VaultAuthError) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      this._emit(AuditEventType.AUTH_FAILURE, { detail: "method=approle", success: false });
      if (msg.includes("invalid") || msg.includes("400")) {
        throw new VaultAuthError("approle", msg);
      }
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  async authOidc(role: string = "", mountPoint: string = "oidc"): Promise<void> {
    const jwtToken = process.env["VAULT_OIDC_TOKEN"] ?? "";

    if (jwtToken) {
      try {
        const result = await this._backend.write(`auth/${mountPoint}/login`, {
          role,
          jwt: jwtToken,
        });
        const auth = result?.["auth"] as Record<string, unknown> | undefined;
        this._token = auth?.["client_token"] as string;
        this._emit(AuditEventType.AUTH_SUCCESS, { detail: "method=oidc/jwt" });
        return;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this._emit(AuditEventType.AUTH_FAILURE, { detail: "method=oidc/jwt", success: false });
        throw new VaultAuthError("oidc", msg);
      }
    }

    throw new VaultAuthError(
      "oidc",
      "Interactive OIDC not supported. Set VAULT_OIDC_TOKEN for headless JWT login."
    );
  }

  // ------------------------------------------------------------------
  // KV v2 Operations
  // ------------------------------------------------------------------

  async kvRead(path: string, version?: number): Promise<Record<string, unknown>> {
    try {
      const vaultPath = `${this._kvMount}/data/${path}${version !== undefined ? `?version=${version}` : ""}`;
      const result = await this._backend.read(vaultPath);
      this._emit(AuditEventType.SECRET_READ, { path: `${this._kvMount}/${path}` });

      const data = result?.["data"] as Record<string, unknown> | undefined;
      const secretData = data?.["data"] as Record<string, unknown> | undefined;
      if (!secretData) {
        throw new VaultSecretNotFound(path);
      }
      return secretData;
    } catch (err) {
      if (err instanceof VaultSecretNotFound) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("404") || msg.includes("not found") || msg.includes("Invalid path")) {
        this._emit(AuditEventType.SECRET_READ, {
          path: `${this._kvMount}/${path}`,
          success: false,
        });
        throw new VaultSecretNotFound(path);
      }
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  async kvWrite(path: string, data: Record<string, unknown>): Promise<SecretMetadata> {
    try {
      const result = await this._backend.write(`${this._kvMount}/data/${path}`, {
        data,
      });
      this._emit(AuditEventType.SECRET_WRITE, { path: `${this._kvMount}/${path}` });

      const meta = (result?.["data"] ?? {}) as Record<string, unknown>;
      return {
        path,
        version: (meta["version"] as number) ?? 1,
        created_time: (meta["created_time"] as string) ?? null,
        destroyed: false,
        custom_metadata: {},
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  async kvList(path: string = ""): Promise<string[]> {
    try {
      const result = await this._backend.list(`${this._kvMount}/metadata/${path}`);
      const data = result?.["data"] as Record<string, unknown> | undefined;
      return (data?.["keys"] as string[]) ?? [];
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("404") || msg.includes("not found") || msg.includes("Invalid path")) {
        throw new VaultSecretNotFound(path);
      }
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  async kvMetadata(path: string): Promise<SecretMetadata> {
    try {
      const result = await this._backend.read(`${this._kvMount}/metadata/${path}`);
      if (!result) throw new VaultSecretNotFound(path);

      const data = (result["data"] ?? {}) as Record<string, unknown>;
      const currentVersion = (data["current_version"] as number) ?? 1;
      const versions = (data["versions"] ?? {}) as Record<string, Record<string, unknown>>;
      const versionData = versions[String(currentVersion)] ?? {};

      return {
        path,
        version: currentVersion,
        created_time: (versionData["created_time"] as string) ?? null,
        destroyed: (versionData["destroyed"] as boolean) ?? false,
        custom_metadata: ((data["custom_metadata"] as Record<string, string>) ?? {}),
      };
    } catch (err) {
      if (err instanceof VaultSecretNotFound) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("404") || msg.includes("Invalid path")) {
        throw new VaultSecretNotFound(path);
      }
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  // ------------------------------------------------------------------
  // Dynamic Database Credentials
  // ------------------------------------------------------------------

  async dbCreds(role: string, mountPoint: string = "database"): Promise<LeaseInfo> {
    try {
      const result = await this._backend.read(`${mountPoint}/creds/${role}`);
      return {
        lease_id: (result["lease_id"] as string) ?? "",
        lease_duration: (result["lease_duration"] as number) ?? 0,
        renewable: (result["renewable"] as boolean) ?? false,
        request_id: (result["request_id"] as string) ?? "",
        data: (result["data"] as Record<string, unknown>) ?? {},
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  // ------------------------------------------------------------------
  // PKI Certificate Issuance
  // ------------------------------------------------------------------

  async pkiIssue(
    role: string,
    commonName: string,
    altNames?: string[],
    ttl: string = "8760h",
    mountPoint: string = "pki"
  ): Promise<CertInfo> {
    try {
      const payload: Record<string, unknown> = {
        common_name: commonName,
        ttl,
      };
      if (altNames?.length) {
        payload["alt_names"] = altNames.join(",");
      }

      const result = await this._backend.write(
        `${mountPoint}/issue/${role}`,
        payload
      );
      const data = (result?.["data"] ?? {}) as Record<string, unknown>;
      this._emit(AuditEventType.CERT_ISSUE, { path: `${mountPoint}/issue/${role}` });

      return {
        certificate: (data["certificate"] as string) ?? "",
        issuing_ca: (data["issuing_ca"] as string) ?? "",
        ca_chain: (data["ca_chain"] as string[]) ?? [],
        private_key: (data["private_key"] as string) ?? "",
        private_key_type: (data["private_key_type"] as string) ?? "",
        serial_number: (data["serial_number"] as string) ?? "",
        expiration: (data["expiration"] as number) ?? 0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  // ------------------------------------------------------------------
  // SSH Certificate Signing
  // ------------------------------------------------------------------

  async sshSign(
    role: string,
    publicKey: string,
    validPrincipals: string = "",
    ttl: string = "",
    certType: string = "user",
    mountPoint: string = "ssh"
  ): Promise<SSHCertInfo> {
    try {
      const payload: Record<string, unknown> = {
        public_key: publicKey,
        cert_type: certType,
      };
      if (validPrincipals) payload["valid_principals"] = validPrincipals;
      if (ttl) payload["ttl"] = ttl;

      const result = await this._backend.write(
        `${mountPoint}/sign/${role}`,
        payload
      );
      const data = (result?.["data"] ?? {}) as Record<string, unknown>;
      this._emit(AuditEventType.SSH_SIGN, { path: `${mountPoint}/sign/${role}` });

      return {
        signed_key: (data["signed_key"] as string) ?? "",
        serial_number: (data["serial_number"] as string) ?? "",
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  // ------------------------------------------------------------------
  // Transit Encrypt / Decrypt
  // ------------------------------------------------------------------

  async transitEncrypt(
    keyName: string,
    plaintext: string | Buffer,
    mountPoint: string = "transit"
  ): Promise<TransitResult> {
    const plaintextBytes =
      typeof plaintext === "string" ? Buffer.from(plaintext) : plaintext;
    const b64 = plaintextBytes.toString("base64");

    try {
      const result = await this._backend.write(
        `${mountPoint}/encrypt/${keyName}`,
        { plaintext: b64 }
      );
      const data = (result?.["data"] ?? {}) as Record<string, unknown>;
      this._emit(AuditEventType.TRANSIT_ENCRYPT, {
        path: `${mountPoint}/encrypt/${keyName}`,
      });

      return {
        ciphertext: (data["ciphertext"] as string) ?? "",
        key_version: (data["key_version"] as number) ?? 0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  async transitDecrypt(
    keyName: string,
    ciphertext: string,
    mountPoint: string = "transit"
  ): Promise<TransitResult> {
    try {
      const result = await this._backend.write(
        `${mountPoint}/decrypt/${keyName}`,
        { ciphertext }
      );
      const data = (result?.["data"] ?? {}) as Record<string, unknown>;
      const b64 = (data["plaintext"] as string) ?? "";
      const decoded = b64 ? Buffer.from(b64, "base64").toString("utf-8") : "";
      this._emit(AuditEventType.TRANSIT_DECRYPT, {
        path: `${mountPoint}/decrypt/${keyName}`,
      });

      return { plaintext: decoded };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new VaultConnectionError(this._addr, msg);
    }
  }

  // ------------------------------------------------------------------
  // Token Lifecycle
  // ------------------------------------------------------------------

  async tokenRenew(increment: string = "1h"): Promise<Record<string, unknown>> {
    try {
      const result = await this._backend.tokenRenewSelf({ increment });
      this._emit(AuditEventType.LEASE_RENEW, { detail: "self-token" });
      return (result?.["auth"] as Record<string, unknown>) ?? {};
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this._emit(AuditEventType.LEASE_RENEW, { detail: "self-token", success: false });
      throw new VaultLeaseError("self", "renew", msg);
    }
  }

  async tokenRevokeSelf(): Promise<void> {
    try {
      await this._backend.tokenRevokeSelf();
      this._emit(AuditEventType.LEASE_REVOKE, { detail: "self-token" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new VaultLeaseError("self", "revoke", msg);
    }
  }

  async leaseRenew(leaseId: string, increment: number = 3600): Promise<LeaseInfo> {
    try {
      const result = await this._backend.write("sys/leases/renew", {
        lease_id: leaseId,
        increment,
      });
      this._emit(AuditEventType.LEASE_RENEW, { detail: `lease=${leaseId}` });
      return {
        lease_id: (result["lease_id"] as string) ?? leaseId,
        lease_duration: (result["lease_duration"] as number) ?? 0,
        renewable: (result["renewable"] as boolean) ?? false,
        data: {},
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this._emit(AuditEventType.LEASE_RENEW, { detail: `lease=${leaseId}`, success: false });
      throw new VaultLeaseError(leaseId, "renew", msg);
    }
  }

  async leaseRevoke(leaseId: string): Promise<void> {
    try {
      await this._backend.write("sys/leases/revoke", { lease_id: leaseId });
      this._emit(AuditEventType.LEASE_REVOKE, { detail: `lease=${leaseId}` });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new VaultLeaseError(leaseId, "revoke", msg);
    }
  }

  // ------------------------------------------------------------------
  // Token Auto-Renewal
  // ------------------------------------------------------------------

  startTokenRenewal(intervalMs: number = 1800000, increment: string = "1h"): void {
    this.stopTokenRenewal();
    this._renewalTimer = setInterval(async () => {
      try {
        await this.tokenRenew(increment);
      } catch {
        // Renewal failure is logged via audit events
      }
    }, intervalMs);
  }

  stopTokenRenewal(): void {
    if (this._renewalTimer) {
      clearInterval(this._renewalTimer);
      this._renewalTimer = null;
    }
  }

  // ------------------------------------------------------------------
  // Health
  // ------------------------------------------------------------------

  async health(): Promise<HealthReport> {
    const checks: HealthCheck[] = [];

    // Connectivity check
    const t0 = Date.now();
    try {
      const status = await this._backend.health();
      const latency = Date.now() - t0;
      const initialized = status["initialized"] as boolean;
      const sealed = status["sealed"] as boolean;

      if (initialized && !sealed) {
        checks.push({
          name: "vault_connectivity",
          status: HealthStatus.HEALTHY,
          detail: `Vault at ${this._addr} is initialized and unsealed`,
          latency_ms: latency,
        });
      } else if (sealed) {
        checks.push({
          name: "vault_connectivity",
          status: HealthStatus.UNHEALTHY,
          detail: "Vault is sealed",
          latency_ms: latency,
        });
      } else {
        checks.push({
          name: "vault_connectivity",
          status: HealthStatus.DEGRADED,
          detail: "Vault is not initialized",
          latency_ms: latency,
        });
      }
    } catch (err) {
      const latency = Date.now() - t0;
      checks.push({
        name: "vault_connectivity",
        status: HealthStatus.UNHEALTHY,
        detail: err instanceof Error ? err.message : String(err),
        latency_ms: latency,
      });
    }

    // Auth check
    try {
      await this._backend.tokenLookupSelf();
      checks.push({
        name: "vault_auth",
        status: HealthStatus.HEALTHY,
        detail: "Token is valid",
        latency_ms: 0,
      });
    } catch {
      checks.push({
        name: "vault_auth",
        status: HealthStatus.UNHEALTHY,
        detail: "Token is invalid or expired",
        latency_ms: 0,
      });
    }

    return {
      checks,
      timestamp: new Date().toISOString(),
    };
  }

  // ------------------------------------------------------------------
  // Internal
  // ------------------------------------------------------------------

  private _emit(
    eventType: AuditEventType,
    opts: { path?: string; detail?: string; success?: boolean } = {}
  ): void {
    const event = createAuditEvent(eventType, opts);
    this._auditEvents.push(event);
  }
}
