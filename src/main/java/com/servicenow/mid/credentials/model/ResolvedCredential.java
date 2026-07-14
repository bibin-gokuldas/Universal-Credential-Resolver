package com.servicenow.mid.credentials.model;

/**
 * Canonical credential object returned by every vault provider.
 *
 * <p>This is the internal transfer object that maps to ServiceNow's
 * {@code HashMap<String, String>} credential map keys expected by
 * {@code IExternalCredential.resolve()}.</p>
 *
 * <p>ServiceNow MID Server key constants (from agent.jar):</p>
 * <ul>
 *   <li>{@code user_name}       — username / client ID</li>
 *   <li>{@code password}        — password / client secret / token</li>
 *   <li>{@code ssh_private_key} — PEM-encoded private key</li>
 *   <li>{@code ssh_passphrase}  — passphrase for encrypted private key</li>
 *   <li>{@code windows_domain}  — NTLM domain</li>
 *   <li>{@code pki_certificate} — client certificate (PEM)</li>
 *   <li>{@code pki_key}         — private key for mTLS cert</li>
 *   <li>{@code api_key}         — bearer / API token</li>
 *   <li>{@code tenant_id}       — Azure AD tenant ID (SP flows)</li>
 * </ul>
 */
public class ResolvedCredential {

    // ── Core fields ──────────────────────────────────────────────────────────
    private String userName;
    private String password;

    // ── SSH ──────────────────────────────────────────────────────────────────
    private String sshPrivateKey;
    private String sshPassphrase;

    // ── Windows / NTLM ───────────────────────────────────────────────────────
    private String windowsDomain;

    // ── PKI / mTLS ───────────────────────────────────────────────────────────
    private String pkiCertificate;
    private String pkiKey;

    // ── Token / API Key ──────────────────────────────────────────────────────
    private String apiKey;

    // ── Azure SP ─────────────────────────────────────────────────────────────
    private String tenantId;

    // ── Metadata ─────────────────────────────────────────────────────────────
    private CredentialType credentialType;
    private long resolvedAtEpochMs;

    public enum CredentialType {
        USERNAME_PASSWORD,
        SSH_KEY,
        WINDOWS_NTLM,
        API_KEY_BEARER,
        AZURE_SERVICE_PRINCIPAL
    }

    private ResolvedCredential() {}

    // ── Builder ──────────────────────────────────────────────────────────────

    public static Builder builder(CredentialType type) {
        return new Builder(type);
    }

    public static final class Builder {
        private final ResolvedCredential c = new ResolvedCredential();

        private Builder(CredentialType type) {
            c.credentialType = type;
            c.resolvedAtEpochMs = System.currentTimeMillis();
        }

        public Builder userName(String v)       { c.userName = v;       return this; }
        public Builder password(String v)       { c.password = v;       return this; }
        public Builder sshPrivateKey(String v)  { c.sshPrivateKey = v;  return this; }
        public Builder sshPassphrase(String v)  { c.sshPassphrase = v;  return this; }
        public Builder windowsDomain(String v)  { c.windowsDomain = v;  return this; }
        public Builder pkiCertificate(String v) { c.pkiCertificate = v; return this; }
        public Builder pkiKey(String v)         { c.pkiKey = v;         return this; }
        public Builder apiKey(String v)         { c.apiKey = v;         return this; }
        public Builder tenantId(String v)       { c.tenantId = v;       return this; }

        public ResolvedCredential build() {
            if (c.credentialType == null) {
                throw new IllegalStateException("CredentialType must be set");
            }
            return c;
        }
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    public String getUserName()      { return userName; }
    public String getPassword()      { return password; }
    public String getSshPrivateKey() { return sshPrivateKey; }
    public String getSshPassphrase() { return sshPassphrase; }
    public String getWindowsDomain() { return windowsDomain; }
    public String getPkiCertificate(){ return pkiCertificate; }
    public String getPkiKey()        { return pkiKey; }
    public String getApiKey()        { return apiKey; }
    public String getTenantId()      { return tenantId; }
    public CredentialType getCredentialType()   { return credentialType; }
    public long getResolvedAtEpochMs()          { return resolvedAtEpochMs; }

    @Override
    public String toString() {
        return "ResolvedCredential{type=" + credentialType
                + ", user=" + (userName != null ? userName : "<none>")
                + ", resolvedAt=" + resolvedAtEpochMs + "}";
    }
}
