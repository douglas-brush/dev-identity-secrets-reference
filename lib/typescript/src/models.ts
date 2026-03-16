/**
 * Shared data models for the secrets SDK.
 *
 * All interfaces and enums are exported for consumer use.
 */

// ------------------------------------------------------------------
// Secret Metadata
// ------------------------------------------------------------------

export interface SecretMetadata {
  path: string;
  version: number;
  created_time?: string | null;
  deletion_time?: string | null;
  destroyed: boolean;
  custom_metadata: Record<string, string>;
}

export function secretMetadataAgeSeconds(meta: SecretMetadata): number | null {
  if (!meta.created_time) return null;
  const created = new Date(meta.created_time);
  if (isNaN(created.getTime())) return null;
  return (Date.now() - created.getTime()) / 1000;
}

// ------------------------------------------------------------------
// Lease Info
// ------------------------------------------------------------------

export interface LeaseInfo {
  lease_id: string;
  lease_duration: number; // seconds
  renewable: boolean;
  request_id?: string;
  data: Record<string, unknown>;
}

// ------------------------------------------------------------------
// Certificate Info
// ------------------------------------------------------------------

export interface CertInfo {
  certificate: string;
  issuing_ca: string;
  ca_chain: string[];
  private_key: string;
  private_key_type: string;
  serial_number: string;
  expiration: number; // Unix timestamp
}

export function certIsExpired(cert: CertInfo): boolean {
  if (cert.expiration === 0) return false;
  return Date.now() > cert.expiration * 1000;
}

export function certExpiresAt(cert: CertInfo): Date | null {
  if (cert.expiration === 0) return null;
  return new Date(cert.expiration * 1000);
}

// ------------------------------------------------------------------
// SSH Certificate Info
// ------------------------------------------------------------------

export interface SSHCertInfo {
  signed_key: string;
  serial_number: string;
}

// ------------------------------------------------------------------
// Transit Result
// ------------------------------------------------------------------

export interface TransitResult {
  ciphertext?: string;
  plaintext?: string;
  key_version?: number;
}

// ------------------------------------------------------------------
// Audit Events
// ------------------------------------------------------------------

export enum AuditEventType {
  SECRET_READ = "secret_read",
  SECRET_WRITE = "secret_write",
  SECRET_DELETE = "secret_delete",
  SECRET_ROTATE = "secret_rotate",
  AUTH_SUCCESS = "auth_success",
  AUTH_FAILURE = "auth_failure",
  LEASE_RENEW = "lease_renew",
  LEASE_REVOKE = "lease_revoke",
  CERT_ISSUE = "cert_issue",
  SSH_SIGN = "ssh_sign",
  TRANSIT_ENCRYPT = "transit_encrypt",
  TRANSIT_DECRYPT = "transit_decrypt",
  CONFIG_VALIDATE = "config_validate",
  SOPS_DECRYPT = "sops_decrypt",
  SOPS_ENCRYPT = "sops_encrypt",
  SCAN_SECRETS = "scan_secrets",
}

export interface AuditEvent {
  timestamp: string; // ISO 8601
  event_type: AuditEventType;
  path: string;
  success: boolean;
  detail: string;
  actor: string;
}

export function auditEventLogLine(event: AuditEvent): string {
  const status = event.success ? "OK" : "FAIL";
  const parts = [
    `ts=${event.timestamp}`,
    `event=${event.event_type}`,
    `status=${status}`,
  ];
  if (event.path) parts.push(`path=${event.path}`);
  if (event.actor) parts.push(`actor=${event.actor}`);
  if (event.detail) parts.push(`detail=${event.detail}`);
  return parts.join(" ");
}

export function createAuditEvent(
  eventType: AuditEventType,
  opts: { path?: string; detail?: string; success?: boolean; actor?: string } = {}
): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    event_type: eventType,
    path: opts.path ?? "",
    success: opts.success ?? true,
    detail: opts.detail ?? "",
    actor: opts.actor ?? "",
  };
}

// ------------------------------------------------------------------
// Health
// ------------------------------------------------------------------

export enum HealthStatus {
  HEALTHY = "healthy",
  DEGRADED = "degraded",
  UNHEALTHY = "unhealthy",
  UNKNOWN = "unknown",
}

export interface HealthCheck {
  name: string;
  status: HealthStatus;
  detail: string;
  latency_ms: number;
}

export interface HealthReport {
  checks: HealthCheck[];
  timestamp: string; // ISO 8601
}

export function healthReportOverallStatus(report: HealthReport): HealthStatus {
  if (report.checks.length === 0) return HealthStatus.UNKNOWN;
  const statuses = new Set(report.checks.map((c) => c.status));
  if (statuses.has(HealthStatus.UNHEALTHY)) return HealthStatus.UNHEALTHY;
  if (statuses.has(HealthStatus.DEGRADED)) return HealthStatus.DEGRADED;
  if ([...statuses].every((s) => s === HealthStatus.HEALTHY))
    return HealthStatus.HEALTHY;
  return HealthStatus.DEGRADED;
}

export function healthReportSummary(report: HealthReport): string {
  const parts = report.checks.map((c) => `${c.name}: ${c.status}`);
  const overall = healthReportOverallStatus(report).toUpperCase();
  return `[${overall}] ${parts.join(" | ")}`;
}

// ------------------------------------------------------------------
// Secret Finding (scan)
// ------------------------------------------------------------------

export interface SecretFinding {
  file_path: string;
  line_number: number;
  pattern_name: string;
  matched_text: string;
  severity: string;
}

// ------------------------------------------------------------------
// Age Report (rotation)
// ------------------------------------------------------------------

export interface AgeReport {
  path: string;
  current_version: number;
  created_time?: string | null;
  age_days: number;
  max_age_days: number;
  needs_rotation: boolean;
  detail: string;
}
