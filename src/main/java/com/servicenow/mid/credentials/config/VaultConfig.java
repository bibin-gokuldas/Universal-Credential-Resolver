package com.servicenow.mid.credentials.config;

import java.util.Map;

/**
 * Immutable configuration object populated from ServiceNow Credential record
 * attributes and MID Server system properties.
 *
 * <h3>MID Server System Properties (agent/config.xml or ServiceNow UI)</h3>
 * <pre>
 *   mid.external_credentials.vault.type         = hashicorp|cyberark|azure_kv|aws_sm|delinea
 *   mid.external_credentials.vault.url          = https://vault.corp.example.com
 *   mid.external_credentials.vault.namespace    = (HashiCorp Enterprise namespaces)
 *   mid.external_credentials.vault.auth_method  = token|approle|azure_mi|aws_iam|mtls
 *   mid.external_credentials.vault.token        = (static token — auth_method=token only)
 *   mid.external_credentials.vault.role_id      = (AppRole role_id)
 *   mid.external_credentials.vault.secret_id    = (AppRole secret_id)
 *   mid.external_credentials.vault.mount_path   = secret  (KV mount, default "secret")
 *   mid.external_credentials.vault.kv_version   = 2       (1 or 2, HashiCorp only)
 *   mid.external_credentials.vault.mtls_cert    = /path/to/client.pem
 *   mid.external_credentials.vault.mtls_key     = /path/to/client.key
 *   mid.external_credentials.vault.ca_cert      = /path/to/ca.pem  (optional)
 *   mid.external_credentials.vault.timeout_ms   = 10000
 *   mid.external_credentials.vault.retry_count  = 3
 *   mid.external_credentials.aws.region         = ap-southeast-1
 *   mid.external_credentials.azure.tenant_id    = <guid>
 *   mid.external_credentials.azure.client_id    = <guid>  (for non-MI SP auth to AKV)
 *   mid.external_credentials.azure.client_secret= ...
 * </pre>
 *
 * <h3>Credential Record Attributes (passed via IExternalCredential.resolve())</h3>
 * <pre>
 *   credential_id    → Vault secret path / CyberArk Object / AWS secret name / Delinea secret ID
 *   type             → snc_internal type string (ssh_password, windows, snmp, api_key, …)
 *   user_name        → optional hint for vault lookup
 * </pre>
 */
public class VaultConfig {

    // ── Vault backend type ────────────────────────────────────────────────────
    public enum VaultType {
        HASHICORP, CYBERARK, AZURE_KEY_VAULT, AWS_SECRETS_MANAGER, DELINEA
    }

    public enum AuthMethod {
        STATIC_TOKEN, APPROLE, AZURE_MANAGED_IDENTITY, AWS_IAM_ROLE, MTLS
    }

    // ── Common ────────────────────────────────────────────────────────────────
    private final VaultType vaultType;
    private final String vaultUrl;
    private final AuthMethod authMethod;
    private final int timeoutMs;
    private final int retryCount;

    // ── HashiCorp-specific ────────────────────────────────────────────────────
    private final String hcNamespace;
    private final String hcStaticToken;
    private final String hcRoleId;
    private final String hcSecretId;
    private final String hcMountPath;
    private final int    hcKvVersion;

    // ── mTLS ─────────────────────────────────────────────────────────────────
    private final String mtlsCertPath;
    private final String mtlsKeyPath;
    private final String caCertPath;

    // ── AWS-specific ──────────────────────────────────────────────────────────
    private final String awsRegion;

    // ── Azure-specific ────────────────────────────────────────────────────────
    private final String azureTenantId;
    private final String azureClientId;
    private final String azureClientSecret;

    // ── Credential record context ─────────────────────────────────────────────
    private final String credentialId;   // secret path / object name / ARN
    private final String credentialType; // SN type string
    private final String usernameHint;   // optional

    private VaultConfig(Builder b) {
        this.vaultType          = b.vaultType;
        this.vaultUrl           = b.vaultUrl;
        this.authMethod         = b.authMethod;
        this.timeoutMs          = b.timeoutMs;
        this.retryCount         = b.retryCount;
        this.hcNamespace        = b.hcNamespace;
        this.hcStaticToken      = b.hcStaticToken;
        this.hcRoleId           = b.hcRoleId;
        this.hcSecretId         = b.hcSecretId;
        this.hcMountPath        = b.hcMountPath;
        this.hcKvVersion        = b.hcKvVersion;
        this.mtlsCertPath       = b.mtlsCertPath;
        this.mtlsKeyPath        = b.mtlsKeyPath;
        this.caCertPath         = b.caCertPath;
        this.awsRegion          = b.awsRegion;
        this.azureTenantId      = b.azureTenantId;
        this.azureClientId      = b.azureClientId;
        this.azureClientSecret  = b.azureClientSecret;
        this.credentialId       = b.credentialId;
        this.credentialType     = b.credentialType;
        this.usernameHint       = b.usernameHint;
    }

    // ── Factory: parse from MID properties + credential attributes ────────────

    /**
     * Build VaultConfig from MID system properties (via IExternalCredential
     * parameter map) and credential record attributes.
     *
     * @param midProps   map of mid.external_credentials.* system properties
     * @param credAttrs  map of credential record fields from SN
     */
    public static VaultConfig from(Map<String, String> midProps,
                                   Map<String, String> credAttrs) {
        Builder b = new Builder();

        // ── Vault type ──
        String type = require(midProps, "mid.external_credentials.vault.type");
        b.vaultType = VaultType.valueOf(type.toUpperCase().replace("-", "_"));

        // ── Vault URL ──
        b.vaultUrl = require(midProps, "mid.external_credentials.vault.url");

        // ── Auth method ──
        String auth = midProps.getOrDefault("mid.external_credentials.vault.auth_method", "token");
        b.authMethod = parseAuthMethod(auth);

        // ── Timeouts ──
        b.timeoutMs  = parseInt(midProps, "mid.external_credentials.vault.timeout_ms", 10_000);
        b.retryCount = parseInt(midProps, "mid.external_credentials.vault.retry_count", 3);

        // ── HashiCorp ──
        b.hcNamespace   = midProps.get("mid.external_credentials.vault.namespace");
        b.hcStaticToken = midProps.get("mid.external_credentials.vault.token");
        b.hcRoleId      = midProps.get("mid.external_credentials.vault.role_id");
        b.hcSecretId    = midProps.get("mid.external_credentials.vault.secret_id");
        b.hcMountPath   = midProps.getOrDefault("mid.external_credentials.vault.mount_path", "secret");
        b.hcKvVersion   = parseInt(midProps, "mid.external_credentials.vault.kv_version", 2);

        // ── mTLS ──
        b.mtlsCertPath = midProps.get("mid.external_credentials.vault.mtls_cert");
        b.mtlsKeyPath  = midProps.get("mid.external_credentials.vault.mtls_key");
        b.caCertPath   = midProps.get("mid.external_credentials.vault.ca_cert");

        // ── AWS ──
        b.awsRegion = midProps.getOrDefault("mid.external_credentials.aws.region", "us-east-1");

        // ── Azure ──
        b.azureTenantId     = midProps.get("mid.external_credentials.azure.tenant_id");
        b.azureClientId     = midProps.get("mid.external_credentials.azure.client_id");
        b.azureClientSecret = midProps.get("mid.external_credentials.azure.client_secret");

        // ── Credential record ──
        b.credentialId   = require(credAttrs, "credential_id");
        b.credentialType = credAttrs.getOrDefault("type", "ssh_password");
        b.usernameHint   = credAttrs.get("user_name");

        return new VaultConfig(b);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String require(Map<String, String> map, String key) {
        String v = map.get(key);
        if (v == null || v.trim().isEmpty()) {
            throw new IllegalArgumentException("Required config missing: " + key);
        }
        return v.trim();
    }

    private static int parseInt(Map<String, String> map, String key, int defaultVal) {
        String v = map.get(key);
        if (v == null) return defaultVal;
        try { return Integer.parseInt(v.trim()); }
        catch (NumberFormatException e) { return defaultVal; }
    }

    private static AuthMethod parseAuthMethod(String raw) {
        switch (raw.toLowerCase().replace("-", "_")) {
            case "token": case "static_token": return AuthMethod.STATIC_TOKEN;
            case "approle":                    return AuthMethod.APPROLE;
            case "azure_mi": case "azure_managed_identity": return AuthMethod.AZURE_MANAGED_IDENTITY;
            case "aws_iam": case "aws_iam_role":             return AuthMethod.AWS_IAM_ROLE;
            case "mtls": case "mutual_tls":                  return AuthMethod.MTLS;
            default: throw new IllegalArgumentException("Unknown auth_method: " + raw);
        }
    }

    // ── Getters ───────────────────────────────────────────────────────────────

    public VaultType  getVaultType()          { return vaultType; }
    public String     getVaultUrl()           { return vaultUrl; }
    public AuthMethod getAuthMethod()         { return authMethod; }
    public int        getTimeoutMs()          { return timeoutMs; }
    public int        getRetryCount()         { return retryCount; }
    public String     getHcNamespace()        { return hcNamespace; }
    public String     getHcStaticToken()      { return hcStaticToken; }
    public String     getHcRoleId()           { return hcRoleId; }
    public String     getHcSecretId()         { return hcSecretId; }
    public String     getHcMountPath()        { return hcMountPath; }
    public int        getHcKvVersion()        { return hcKvVersion; }
    public String     getMtlsCertPath()       { return mtlsCertPath; }
    public String     getMtlsKeyPath()        { return mtlsKeyPath; }
    public String     getCaCertPath()         { return caCertPath; }
    public String     getAwsRegion()          { return awsRegion; }
    public String     getAzureTenantId()      { return azureTenantId; }
    public String     getAzureClientId()      { return azureClientId; }
    public String     getAzureClientSecret()  { return azureClientSecret; }
    public String     getCredentialId()       { return credentialId; }
    public String     getCredentialType()     { return credentialType; }
    public String     getUsernameHint()       { return usernameHint; }

    // ── Builder ───────────────────────────────────────────────────────────────

    private static class Builder {
        VaultType  vaultType; String vaultUrl; AuthMethod authMethod;
        int timeoutMs; int retryCount;
        String hcNamespace; String hcStaticToken; String hcRoleId;
        String hcSecretId;  String hcMountPath;   int hcKvVersion;
        String mtlsCertPath; String mtlsKeyPath; String caCertPath;
        String awsRegion;
        String azureTenantId; String azureClientId; String azureClientSecret;
        String credentialId;  String credentialType; String usernameHint;
    }
}
