// Vault-integrated .NET application demonstrating OIDC/AppRole auth,
// KV v2 secret reading, dynamic database credentials, and a Minimal API
// health endpoint.
//
// Environment variables:
//   VAULT_ADDR          - Vault server URL (required)
//   VAULT_AUTH_METHOD   - "oidc" or "approle" (default: approle)
//   VAULT_ROLE          - Vault role name for authentication
//   VAULT_ROLE_ID       - AppRole role ID (required if approle)
//   VAULT_SECRET_ID     - AppRole secret ID (required if approle)
//   VAULT_OIDC_TOKEN    - Pre-obtained OIDC JWT (required if oidc)
//   VAULT_KV_PATH       - KV v2 mount + path (default: kv/dev/apps/myapp/config)
//   VAULT_DB_ROLE       - Database secret engine role (default: myapp-db)
//   VAULT_NAMESPACE     - Vault namespace (optional, enterprise)

using System.Collections.Concurrent;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.AppRole;
using VaultSharp.V1.AuthMethods.JWT;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

var vaultAddr = Environment.GetEnvironmentVariable("VAULT_ADDR")
    ?? throw new InvalidOperationException("VAULT_ADDR is required");
var authMethod = Environment.GetEnvironmentVariable("VAULT_AUTH_METHOD") ?? "approle";
var role = Environment.GetEnvironmentVariable("VAULT_ROLE") ?? "myapp";
var kvPath = Environment.GetEnvironmentVariable("VAULT_KV_PATH") ?? "kv/dev/apps/myapp/config";
var dbRole = Environment.GetEnvironmentVariable("VAULT_DB_ROLE") ?? "myapp-db";
var vaultNamespace = Environment.GetEnvironmentVariable("VAULT_NAMESPACE");

// ---------------------------------------------------------------------------
// State tracking for health endpoint
// ---------------------------------------------------------------------------

var state = new AppState();
var cts = new CancellationTokenSource();

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// Build the auth method. AppRole uses role_id + secret_id delivered by
// a trusted orchestrator. OIDC uses a pre-obtained JWT for headless envs.
IAuthMethodInfo authInfo = authMethod switch
{
    "approle" => new AppRoleAuthMethodInfo(
        Environment.GetEnvironmentVariable("VAULT_ROLE_ID")
            ?? throw new InvalidOperationException("VAULT_ROLE_ID required for AppRole"),
        Environment.GetEnvironmentVariable("VAULT_SECRET_ID")
            ?? throw new InvalidOperationException("VAULT_SECRET_ID required for AppRole")
    ),
    "oidc" => new JWTAuthMethodInfo(
        role,
        Environment.GetEnvironmentVariable("VAULT_OIDC_TOKEN")
            ?? throw new InvalidOperationException("VAULT_OIDC_TOKEN required for OIDC")
    ),
    _ => throw new InvalidOperationException($"Unsupported auth method: {authMethod}")
};

var vaultSettings = new VaultClientSettings(vaultAddr, authInfo)
{
    Namespace = vaultNamespace,
    // ContinueAsyncTasksOnCapturedContext is false by default,
    // which is correct for ASP.NET / server workloads.
};
var vaultClient = new VaultClient(vaultSettings);

Console.WriteLine($"[vault] Authenticating via {authMethod}...");
state.Authenticated = true;
Console.WriteLine($"[vault] Authenticated via {authMethod}");

// ---------------------------------------------------------------------------
// Read KV v2 secrets
// ---------------------------------------------------------------------------

// Split path into mount point and secret path.
// Convention: first segment is the mount, rest is the path.
var kvParts = kvPath.Split('/', 2);
var kvMount = kvParts[0];
var kvSecretPath = kvParts.Length > 1 ? kvParts[1] : "";

try
{
    var kvResponse = await vaultClient.V1.Secrets.KeyValue.V2
        .ReadSecretAsync(kvSecretPath, mountPoint: kvMount);

    state.KvSecrets = new Dictionary<string, object>(
        kvResponse.Data.Data.Select(kv =>
            new KeyValuePair<string, object>(kv.Key, kv.Value ?? ""))
    );
    state.KvLoadedAt = DateTime.UtcNow;

    // Export to environment for child processes or framework config
    foreach (var (key, value) in state.KvSecrets)
    {
        var envKey = $"APP_{key.ToUpperInvariant()}";
        Environment.SetEnvironmentVariable(envKey, value?.ToString());
    }

    Console.WriteLine($"[vault] Read {state.KvSecrets.Count} KV secrets from {kvPath}");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[vault] Failed to read KV secrets: {ex.Message}");
    state.Errors.Add(new AppStateError(DateTime.UtcNow, ex.Message));
    throw;
}

// ---------------------------------------------------------------------------
// Dynamic database credentials
// ---------------------------------------------------------------------------

// Dynamic credentials are short-lived and tied to a Vault lease.
// The application must handle credential rotation by catching connection
// errors and re-acquiring credentials from Vault.
try
{
    var dbCreds = await vaultClient.V1.Secrets.Database
        .GetCredentialsAsync(dbRole);

    state.DbUsername = dbCreds.Data.Username;
    state.DbLeaseId = dbCreds.LeaseId;
    state.DbLeaseExpiry = DateTime.UtcNow.AddSeconds(dbCreds.LeaseDurationSeconds);

    Environment.SetEnvironmentVariable("APP_DB_USERNAME", dbCreds.Data.Username);
    Environment.SetEnvironmentVariable("APP_DB_PASSWORD", dbCreds.Data.Password);

    Console.WriteLine($"[vault] DB creds acquired: user={dbCreds.Data.Username} " +
                      $"TTL={dbCreds.LeaseDurationSeconds}s");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[vault] Failed to get DB credentials: {ex.Message}");
    state.Errors.Add(new AppStateError(DateTime.UtcNow, ex.Message));
    throw;
}

// ---------------------------------------------------------------------------
// Background lease renewal
// ---------------------------------------------------------------------------

// Renewal runs at 2/3 of the lease TTL. After 3 consecutive failures,
// the app logs a critical error. VaultSharp handles token renewal
// internally via its auth provider, so we focus on DB lease renewal.
_ = Task.Run(async () =>
{
    var failures = 0;
    while (!cts.Token.IsCancellationRequested)
    {
        var sleepSeconds = Math.Max(
            (int)(state.DbLeaseExpiry - DateTime.UtcNow).TotalSeconds * 2 / 3,
            5
        );
        await Task.Delay(TimeSpan.FromSeconds(sleepSeconds), cts.Token);

        if (string.IsNullOrEmpty(state.DbLeaseId)) continue;

        try
        {
            await vaultClient.V1.System.RenewLeaseAsync(
                state.DbLeaseId,
                (int)(state.DbLeaseExpiry - DateTime.UtcNow).TotalSeconds
            );
            state.DbLeaseExpiry = DateTime.UtcNow.AddSeconds(sleepSeconds * 3 / 2);
            state.RenewalActive = true;
            failures = 0;
            Console.WriteLine("[vault] DB lease renewed");
        }
        catch (Exception ex)
        {
            failures++;
            state.Errors.Add(new AppStateError(DateTime.UtcNow, ex.Message));
            Console.Error.WriteLine(
                $"[vault] Lease renewal failed (attempt {failures}): {ex.Message}");

            if (failures >= 3)
            {
                Console.Error.WriteLine("[vault] 3 consecutive renewal failures — " +
                                        "DB credentials may be stale");
                state.RenewalActive = false;
                // Re-acquire credentials
                try
                {
                    var newCreds = await vaultClient.V1.Secrets.Database
                        .GetCredentialsAsync(dbRole);
                    state.DbUsername = newCreds.Data.Username;
                    state.DbLeaseId = newCreds.LeaseId;
                    state.DbLeaseExpiry = DateTime.UtcNow
                        .AddSeconds(newCreds.LeaseDurationSeconds);
                    Environment.SetEnvironmentVariable(
                        "APP_DB_USERNAME", newCreds.Data.Username);
                    Environment.SetEnvironmentVariable(
                        "APP_DB_PASSWORD", newCreds.Data.Password);
                    state.RenewalActive = true;
                    failures = 0;
                    Console.WriteLine("[vault] Re-acquired DB credentials");
                }
                catch (Exception reEx)
                {
                    Console.Error.WriteLine(
                        $"[vault] Re-acquire DB creds failed: {reEx.Message}");
                }
            }
        }
    }
}, cts.Token);

state.RenewalActive = true;
Console.WriteLine("[vault] Integration ready — secrets loaded, renewal active");

// ---------------------------------------------------------------------------
// Minimal API health endpoint
// ---------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Health endpoint exposes secret metadata (never values) for observability.
app.MapGet("/health", () =>
{
    var dbExpired = state.DbLeaseExpiry != default && DateTime.UtcNow > state.DbLeaseExpiry;
    var healthy = state.Authenticated && !dbExpired && state.RenewalActive;

    var response = new
    {
        status = healthy ? "healthy" : "degraded",
        vault = new { state.Authenticated, state.RenewalActive },
        kv = new
        {
            loaded = state.KvLoadedAt.HasValue,
            loadedAt = state.KvLoadedAt?.ToString("o"),
            keyCount = state.KvSecrets?.Count ?? 0,
        },
        database = new
        {
            credentialsActive = !string.IsNullOrEmpty(state.DbUsername),
            username = state.DbUsername,
            leaseExpired = dbExpired,
            expiresAt = state.DbLeaseExpiry.ToString("o"),
        },
        recentErrors = state.Errors.TakeLast(5).Select(e => new
        {
            time = e.Time.ToString("o"),
            error = e.Message,
        }),
    };

    return healthy ? Results.Ok(response) : Results.Json(response, statusCode: 503);
});

// Graceful shutdown
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    Console.WriteLine("[vault] Shutting down");
    cts.Cancel();
});

app.Run();

// ---------------------------------------------------------------------------
// State model
// ---------------------------------------------------------------------------

record AppStateError(DateTime Time, string Message);

class AppState
{
    public bool Authenticated { get; set; }
    public Dictionary<string, object>? KvSecrets { get; set; }
    public DateTime? KvLoadedAt { get; set; }
    public string? DbUsername { get; set; }
    public string? DbLeaseId { get; set; }
    public DateTime DbLeaseExpiry { get; set; }
    public bool RenewalActive { get; set; }
    public ConcurrentBag<AppStateError> Errors { get; } = new();
}
