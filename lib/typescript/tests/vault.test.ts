/**
 * Unit tests for the Vault client wrapper.
 */

import {
  VaultClient,
  VaultBackend,
  VaultAuthError,
  VaultConnectionError,
  VaultLeaseError,
  VaultSecretNotFound,
  AuditEventType,
  HealthStatus,
  healthReportOverallStatus,
} from "../src";

// ------------------------------------------------------------------
// Mock Backend
// ------------------------------------------------------------------

function createMockBackend(): jest.Mocked<VaultBackend> {
  return {
    read: jest.fn(),
    write: jest.fn(),
    delete: jest.fn(),
    list: jest.fn(),
    health: jest.fn(),
    tokenLookupSelf: jest.fn(),
    tokenRenewSelf: jest.fn(),
    tokenRevokeSelf: jest.fn(),
  };
}

function createClient(backend: VaultBackend): VaultClient {
  return new VaultClient({
    addr: "http://127.0.0.1:8200",
    backend,
    token: "s.mock-token",
  });
}

// ------------------------------------------------------------------
// Authentication
// ------------------------------------------------------------------

describe("Token Auth", () => {
  test("auth_token success", async () => {
    const backend = createMockBackend();
    backend.tokenLookupSelf.mockResolvedValue({ data: { id: "s.valid" } });
    const client = createClient(backend);

    await client.authToken("s.valid-token");
    expect(backend.tokenLookupSelf).toHaveBeenCalledTimes(1);
  });

  test("auth_token no token throws VaultAuthError", async () => {
    const backend = createMockBackend();
    const client = new VaultClient({ addr: "http://x:8200", backend });
    const originalEnv = process.env["VAULT_TOKEN"];
    delete process.env["VAULT_TOKEN"];

    try {
      await expect(client.authToken(undefined)).rejects.toThrow(VaultAuthError);
      await expect(client.authToken(undefined)).rejects.toThrow("No token provided");
    } finally {
      if (originalEnv) process.env["VAULT_TOKEN"] = originalEnv;
    }
  });

  test("auth_token forbidden throws VaultAuthError", async () => {
    const backend = createMockBackend();
    backend.tokenLookupSelf.mockRejectedValue(new Error("403 permission denied"));
    const client = createClient(backend);

    await expect(client.authToken("s.bad")).rejects.toThrow(VaultAuthError);
    await expect(client.authToken("s.bad")).rejects.toThrow("invalid or expired");
  });

  test("auth_token connection error throws VaultConnectionError", async () => {
    const backend = createMockBackend();
    backend.tokenLookupSelf.mockRejectedValue(new Error("ECONNREFUSED"));
    const client = createClient(backend);

    await expect(client.authToken("s.token")).rejects.toThrow(VaultConnectionError);
  });
});

describe("AppRole Auth", () => {
  test("auth_approle success", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({
      auth: { client_token: "s.approle-token" },
    });
    const client = createClient(backend);

    await client.authAppRole("role-123", "secret-456");
    expect(backend.write).toHaveBeenCalledWith("auth/approle/login", {
      role_id: "role-123",
      secret_id: "secret-456",
    });
  });

  test("auth_approle no role_id throws VaultAuthError", async () => {
    const backend = createMockBackend();
    const client = createClient(backend);

    await expect(client.authAppRole("", "secret")).rejects.toThrow(VaultAuthError);
    await expect(client.authAppRole("", "secret")).rejects.toThrow("No role_id");
  });

  test("auth_approle invalid creds throws VaultAuthError", async () => {
    const backend = createMockBackend();
    backend.write.mockRejectedValue(new Error("400 invalid credentials"));
    const client = createClient(backend);

    await expect(client.authAppRole("bad", "creds")).rejects.toThrow(VaultAuthError);
  });
});

describe("OIDC Auth", () => {
  test("auth_oidc jwt login", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({
      auth: { client_token: "s.oidc-token" },
    });
    const client = createClient(backend);

    const original = process.env["VAULT_OIDC_TOKEN"];
    process.env["VAULT_OIDC_TOKEN"] = "eyJ.test.jwt";
    try {
      await client.authOidc("dev");
      expect(backend.write).toHaveBeenCalledWith("auth/oidc/login", {
        role: "dev",
        jwt: "eyJ.test.jwt",
      });
    } finally {
      if (original) process.env["VAULT_OIDC_TOKEN"] = original;
      else delete process.env["VAULT_OIDC_TOKEN"];
    }
  });

  test("auth_oidc no token throws VaultAuthError", async () => {
    const backend = createMockBackend();
    const client = createClient(backend);

    const original = process.env["VAULT_OIDC_TOKEN"];
    delete process.env["VAULT_OIDC_TOKEN"];
    try {
      await expect(client.authOidc()).rejects.toThrow(VaultAuthError);
      await expect(client.authOidc()).rejects.toThrow("Interactive OIDC not supported");
    } finally {
      if (original) process.env["VAULT_OIDC_TOKEN"] = original;
    }
  });
});

// ------------------------------------------------------------------
// KV v2
// ------------------------------------------------------------------

describe("KV Read", () => {
  test("read success", async () => {
    const backend = createMockBackend();
    backend.read.mockResolvedValue({
      data: { data: { username: "admin", password: "s3cret" } },
    });
    const client = createClient(backend);

    const data = await client.kvRead("dev/apps/myapp");
    expect(data).toEqual({ username: "admin", password: "s3cret" });
  });

  test("read not found throws VaultSecretNotFound", async () => {
    const backend = createMockBackend();
    backend.read.mockRejectedValue(new Error("404 not found"));
    const client = createClient(backend);

    await expect(client.kvRead("dev/apps/missing")).rejects.toThrow(VaultSecretNotFound);
  });

  test("read with version", async () => {
    const backend = createMockBackend();
    backend.read.mockResolvedValue({
      data: { data: { key: "value" } },
    });
    const client = createClient(backend);

    await client.kvRead("dev/apps/myapp", 2);
    expect(backend.read).toHaveBeenCalledWith("kv/data/dev/apps/myapp?version=2");
  });
});

describe("KV Write", () => {
  test("write success", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({
      data: { version: 4, created_time: "2024-01-01T00:00:00Z" },
    });
    const client = createClient(backend);

    const meta = await client.kvWrite("dev/apps/myapp", { key: "value" });
    expect(meta.version).toBe(4);
    expect(meta.path).toBe("dev/apps/myapp");
  });

  test("write connection error", async () => {
    const backend = createMockBackend();
    backend.write.mockRejectedValue(new Error("ECONNREFUSED"));
    const client = createClient(backend);

    await expect(client.kvWrite("dev/x", { k: "v" })).rejects.toThrow(VaultConnectionError);
  });
});

describe("KV List", () => {
  test("list success", async () => {
    const backend = createMockBackend();
    backend.list.mockResolvedValue({
      data: { keys: ["app1/", "app2/", "shared/"] },
    });
    const client = createClient(backend);

    const keys = await client.kvList("dev/apps");
    expect(keys).toEqual(["app1/", "app2/", "shared/"]);
  });

  test("list not found throws VaultSecretNotFound", async () => {
    const backend = createMockBackend();
    backend.list.mockRejectedValue(new Error("404 not found"));
    const client = createClient(backend);

    await expect(client.kvList("nonexistent/")).rejects.toThrow(VaultSecretNotFound);
  });
});

describe("KV Metadata", () => {
  test("metadata success", async () => {
    const backend = createMockBackend();
    backend.read.mockResolvedValue({
      data: {
        current_version: 3,
        versions: {
          "3": { created_time: "2024-01-01T00:00:00Z", destroyed: false },
        },
        custom_metadata: { owner: "team-platform" },
      },
    });
    const client = createClient(backend);

    const meta = await client.kvMetadata("dev/apps/myapp");
    expect(meta.version).toBe(3);
    expect(meta.custom_metadata).toEqual({ owner: "team-platform" });
    expect(meta.destroyed).toBe(false);
  });

  test("metadata not found throws VaultSecretNotFound", async () => {
    const backend = createMockBackend();
    backend.read.mockRejectedValue(new Error("404 Invalid path"));
    const client = createClient(backend);

    await expect(client.kvMetadata("missing/path")).rejects.toThrow(VaultSecretNotFound);
  });
});

// ------------------------------------------------------------------
// Dynamic DB Creds
// ------------------------------------------------------------------

describe("DB Creds", () => {
  test("db_creds success", async () => {
    const backend = createMockBackend();
    backend.read.mockResolvedValue({
      lease_id: "database/creds/dev-app/abc123",
      lease_duration: 3600,
      renewable: true,
      request_id: "req-123",
      data: { username: "v-dev-app-abc", password: "secret" },
    });
    const client = createClient(backend);

    const lease = await client.dbCreds("dev-app");
    expect(lease.lease_duration).toBe(3600);
    expect(lease.renewable).toBe(true);
    expect(lease.data["username"]).toBe("v-dev-app-abc");
  });
});

// ------------------------------------------------------------------
// PKI
// ------------------------------------------------------------------

describe("PKI", () => {
  test("pki_issue success", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({
      data: {
        certificate: "-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----",
        issuing_ca: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
        ca_chain: [],
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----",
        private_key_type: "rsa",
        serial_number: "aa:bb:cc:dd",
        expiration: 1700000000,
      },
    });
    const client = createClient(backend);

    const cert = await client.pkiIssue("web-server", "app.example.com");
    expect(cert.certificate).toContain("CERTIFICATE");
    expect(cert.serial_number).toBe("aa:bb:cc:dd");
  });

  test("pki_issue with alt names", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({ data: {} });
    const client = createClient(backend);

    await client.pkiIssue("web", "app.example.com", ["api.example.com"]);
    expect(backend.write).toHaveBeenCalledWith("pki/issue/web", {
      common_name: "app.example.com",
      ttl: "8760h",
      alt_names: "api.example.com",
    });
  });
});

// ------------------------------------------------------------------
// SSH
// ------------------------------------------------------------------

describe("SSH Sign", () => {
  test("ssh_sign success", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({
      data: {
        signed_key: "ssh-rsa-cert-v01@openssh.com AAAA...",
        serial_number: "12345",
      },
    });
    const client = createClient(backend);

    const result = await client.sshSign("dev-admin", "ssh-rsa AAAA...");
    expect(result.signed_key).toContain("ssh-rsa-cert");
  });
});

// ------------------------------------------------------------------
// Transit
// ------------------------------------------------------------------

describe("Transit", () => {
  test("encrypt success", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({
      data: { ciphertext: "vault:v1:ENCRYPTED_DATA", key_version: 1 },
    });
    const client = createClient(backend);

    const result = await client.transitEncrypt("my-key", "hello world");
    expect(result.ciphertext).toBe("vault:v1:ENCRYPTED_DATA");
  });

  test("encrypt bytes (Buffer)", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({
      data: { ciphertext: "vault:v1:ENCRYPTED_DATA" },
    });
    const client = createClient(backend);

    const result = await client.transitEncrypt("my-key", Buffer.from("binary data"));
    expect(result.ciphertext).toBe("vault:v1:ENCRYPTED_DATA");
  });

  test("decrypt success", async () => {
    const backend = createMockBackend();
    const b64 = Buffer.from("hello world").toString("base64");
    backend.write.mockResolvedValue({
      data: { plaintext: b64 },
    });
    const client = createClient(backend);

    const result = await client.transitDecrypt("my-key", "vault:v1:ENCRYPTED_DATA");
    expect(result.plaintext).toBe("hello world");
  });
});

// ------------------------------------------------------------------
// Token Lifecycle
// ------------------------------------------------------------------

describe("Token Lifecycle", () => {
  test("renew_self", async () => {
    const backend = createMockBackend();
    backend.tokenRenewSelf.mockResolvedValue({
      auth: { client_token: "s.mock-token", policies: ["default"] },
    });
    const client = createClient(backend);

    const info = await client.tokenRenew("2h");
    expect(info["client_token"]).toBe("s.mock-token");
  });

  test("revoke_self", async () => {
    const backend = createMockBackend();
    backend.tokenRevokeSelf.mockResolvedValue(undefined);
    const client = createClient(backend);

    await client.tokenRevokeSelf();
    expect(backend.tokenRevokeSelf).toHaveBeenCalledTimes(1);
  });

  test("renew_self error throws VaultLeaseError", async () => {
    const backend = createMockBackend();
    backend.tokenRenewSelf.mockRejectedValue(new Error("403 denied"));
    const client = createClient(backend);

    await expect(client.tokenRenew()).rejects.toThrow(VaultLeaseError);
  });
});

describe("Lease Management", () => {
  test("lease_renew", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({
      lease_id: "database/creds/dev-app/abc123",
      lease_duration: 7200,
      renewable: true,
    });
    const client = createClient(backend);

    const result = await client.leaseRenew("database/creds/dev-app/abc123", 7200);
    expect(result.lease_duration).toBe(7200);
  });

  test("lease_revoke", async () => {
    const backend = createMockBackend();
    backend.write.mockResolvedValue({});
    const client = createClient(backend);

    await client.leaseRevoke("database/creds/dev-app/abc123");
    expect(backend.write).toHaveBeenCalledWith("sys/leases/revoke", {
      lease_id: "database/creds/dev-app/abc123",
    });
  });
});

// ------------------------------------------------------------------
// Health
// ------------------------------------------------------------------

describe("Health", () => {
  test("health ok", async () => {
    const backend = createMockBackend();
    backend.health.mockResolvedValue({ initialized: true, sealed: false });
    backend.tokenLookupSelf.mockResolvedValue({ data: {} });
    const client = createClient(backend);

    const report = await client.health();
    expect(healthReportOverallStatus(report)).toBe(HealthStatus.HEALTHY);
    expect(report.checks.length).toBe(2);
  });

  test("health sealed", async () => {
    const backend = createMockBackend();
    backend.health.mockResolvedValue({ initialized: true, sealed: true });
    backend.tokenLookupSelf.mockResolvedValue({ data: {} });
    const client = createClient(backend);

    const report = await client.health();
    expect(healthReportOverallStatus(report)).toBe(HealthStatus.UNHEALTHY);
  });

  test("health unreachable", async () => {
    const backend = createMockBackend();
    backend.health.mockRejectedValue(new Error("ECONNREFUSED"));
    backend.tokenLookupSelf.mockRejectedValue(new Error("ECONNREFUSED"));
    const client = createClient(backend);

    const report = await client.health();
    expect(healthReportOverallStatus(report)).toBe(HealthStatus.UNHEALTHY);
  });
});

// ------------------------------------------------------------------
// Audit Log
// ------------------------------------------------------------------

describe("Audit Log", () => {
  test("audit events collected on read", async () => {
    const backend = createMockBackend();
    backend.read.mockResolvedValue({
      data: { data: { key: "val" } },
    });
    const client = createClient(backend);

    await client.kvRead("test/path");
    const events = client.auditLog;
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[events.length - 1]!.event_type).toBe(AuditEventType.SECRET_READ);
  });

  test("audit event log line format", async () => {
    const backend = createMockBackend();
    backend.read.mockResolvedValue({
      data: { data: { key: "val" } },
    });
    const client = createClient(backend);

    await client.kvRead("test/path");
    const { auditEventLogLine } = require("../src/models");
    const line = auditEventLogLine(client.auditLog[client.auditLog.length - 1]!);
    expect(line).toContain("event=secret_read");
    expect(line).toContain("status=OK");
  });
});

// ------------------------------------------------------------------
// Constructor
// ------------------------------------------------------------------

describe("Constructor", () => {
  test("from env vars", () => {
    const original = {
      addr: process.env["VAULT_ADDR"],
      skip: process.env["VAULT_SKIP_VERIFY"],
    };
    process.env["VAULT_ADDR"] = "http://env-vault:8200";
    process.env["VAULT_SKIP_VERIFY"] = "true";

    try {
      const backend = createMockBackend();
      const client = new VaultClient({ backend });
      expect(client.addr).toBe("http://env-vault:8200");
    } finally {
      if (original.addr) process.env["VAULT_ADDR"] = original.addr;
      else delete process.env["VAULT_ADDR"];
      if (original.skip) process.env["VAULT_SKIP_VERIFY"] = original.skip;
      else delete process.env["VAULT_SKIP_VERIFY"];
    }
  });

  test("explicit config", () => {
    const backend = createMockBackend();
    const client = new VaultClient({
      addr: "http://x:1234",
      namespace: "ns1",
      verify: true,
      backend,
    });
    expect(client.addr).toBe("http://x:1234");
    expect(client.backend).toBe(backend);
  });
});

// ------------------------------------------------------------------
// Token Auto-Renewal
// ------------------------------------------------------------------

describe("Token Auto-Renewal", () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  test("startTokenRenewal calls renew on interval", async () => {
    const backend = createMockBackend();
    backend.tokenRenewSelf.mockResolvedValue({ auth: { client_token: "s.t" } });
    const client = createClient(backend);

    client.startTokenRenewal(1000, "1h");
    jest.advanceTimersByTime(3500);
    // Allow pending microtasks
    await Promise.resolve();
    client.stopTokenRenewal();

    expect(backend.tokenRenewSelf).toHaveBeenCalledTimes(3);
  });

  test("stopTokenRenewal clears interval", () => {
    const backend = createMockBackend();
    const client = createClient(backend);

    client.startTokenRenewal(1000);
    client.stopTokenRenewal();
    jest.advanceTimersByTime(5000);

    expect(backend.tokenRenewSelf).not.toHaveBeenCalled();
  });
});
