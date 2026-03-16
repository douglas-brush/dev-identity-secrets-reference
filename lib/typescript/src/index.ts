/**
 * @brush-cyber/secrets-sdk
 *
 * TypeScript SDK for developer identity and secrets management.
 * Provides typed access to HashiCorp Vault, SOPS encryption/decryption,
 * configuration validation, secret rotation policy, and a CLI toolkit.
 */

// Models
export {
  SecretMetadata,
  secretMetadataAgeSeconds,
  LeaseInfo,
  CertInfo,
  certIsExpired,
  certExpiresAt,
  SSHCertInfo,
  TransitResult,
  AuditEventType,
  AuditEvent,
  auditEventLogLine,
  createAuditEvent,
  HealthStatus,
  HealthCheck,
  HealthReport,
  healthReportOverallStatus,
  healthReportSummary,
  SecretFinding,
  AgeReport,
} from "./models";

// Exceptions
export {
  SecretsSDKError,
  VaultError,
  VaultAuthError,
  VaultSecretNotFound,
  VaultConnectionError,
  VaultLeaseError,
  SopsError,
  SopsDecryptError,
  SopsEncryptError,
  SopsNotInstalledError,
  ConfigValidationError,
  RotationError,
} from "./exceptions";

// Vault Client
export { VaultClient, VaultBackend, VaultClientOptions } from "./vault";

// SOPS
export {
  decryptFile,
  encryptFile,
  parseSopsConfig,
  SopsConfig,
  SopsCreationRule,
  sopsConfigHasCloudKms,
  sopsConfigRulesForPath,
  detectFormat,
  parseDotenv,
} from "./sops";

// Config Validation
export {
  validateRepoStructure,
  validateSopsYaml,
  validateVaultPolicy,
  scanPlaintextSecrets,
} from "./config";

// Rotation
export {
  RotationPolicy,
  createRotationPolicy,
  policyMatchesPath,
  DEFAULT_POLICIES,
  checkSecretAge,
  checkSecretsBatch,
} from "./rotation";
