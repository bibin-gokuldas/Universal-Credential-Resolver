package com.servicenow.mid.credentials.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.servicenow.mid.credentials.core.CredentialResolverException;
import com.servicenow.mid.credentials.core.CredentialResolverException.ErrorCode;
import com.servicenow.mid.credentials.model.ResolvedCredential;
import com.servicenow.mid.credentials.model.ResolvedCredential.CredentialType;

/**
 * Maps a flat key-value map from any vault backend into a typed
 * {@link ResolvedCredential}.
 *
 * <h3>Convention-based field name mapping</h3>
 * <p>The vault secret is expected to contain well-known field names.
 * Aliases are tried in order until a match is found.</p>
 *
 * <pre>
 * ╔══════════════════════╦══════════════════════════════════════════════════════╗
 * ║  SN Credential Type  ║  Expected vault secret keys (first match wins)       ║
 * ╠══════════════════════╬══════════════════════════════════════════════════════╣
 * ║ ssh_password /       ║  username | user_name | user                         ║
 * ║ windows / snmp       ║  password | pass | secret                            ║
 * ╠══════════════════════╬══════════════════════════════════════════════════════╣
 * ║ ssh_private_key      ║  username | user_name                                ║
 * ║                      ║  ssh_private_key | private_key | key                 ║
 * ║                      ║  ssh_passphrase | passphrase (optional)              ║
 * ╠══════════════════════╬══════════════════════════════════════════════════════╣
 * ║ windows              ║  username | user_name                                ║
 * ║                      ║  password | pass                                     ║
 * ║                      ║  windows_domain | domain (optional)                  ║
 * ╠══════════════════════╬══════════════════════════════════════════════════════╣
 * ║ api_key              ║  api_key | token | access_token | bearer_token       ║
 * ╠══════════════════════╬══════════════════════════════════════════════════════╣
 * ║ azure_sp             ║  client_id | application_id                          ║
 * ║                      ║  client_secret | secret                              ║
 * ║                      ║  tenant_id | directory_id (optional override)        ║
 * ╚══════════════════════╩══════════════════════════════════════════════════════╝
 * </pre>
 */
public class CredentialMapper {

    private CredentialMapper() {}

    /**
     * Map a flat JsonNode (vault data object) + SN credential type string
     * into a strongly-typed {@link ResolvedCredential}.
     *
     * @param data         flat JSON object from vault (KV data map)
     * @param snType       ServiceNow credential type string
     * @param usernameHint optional override from the SN credential record
     */
    public static ResolvedCredential map(JsonNode data, String snType,
                                          String usernameHint) {
        if (data == null || data.isNull()) {
            throw new CredentialResolverException(ErrorCode.MISSING_SECRET_FIELD,
                    "Vault returned null/empty data for credential type: " + snType);
        }

        String type = snType == null ? "" : snType.toLowerCase();

        if (type.contains("ssh") && type.contains("key")) {
            return mapSshKey(data, usernameHint);
        }
        if (type.contains("windows") || type.contains("ntlm")) {
            return mapWindows(data, usernameHint);
        }
        if (type.contains("api_key") || type.contains("bearer") || type.contains("token")) {
            return mapApiKey(data);
        }
        if (type.contains("azure") || type.contains("service_principal") || type.contains("sp")) {
            return mapAzureServicePrincipal(data);
        }
        // Default: username + password (covers ssh_password, snmp, basic, etc.)
        return mapUsernamePassword(data, usernameHint);
    }

    // ── Mappers ───────────────────────────────────────────────────────────────

    private static ResolvedCredential mapUsernamePassword(JsonNode data, String hint) {
        String user = hint != null ? hint : firstPresent(data,
                "username", "user_name", "user", "login");
        String pass = requireField(data, "password", "pass", "secret", "passwd");
        return ResolvedCredential.builder(CredentialType.USERNAME_PASSWORD)
                .userName(user)
                .password(pass)
                .build();
    }

    private static ResolvedCredential mapSshKey(JsonNode data, String hint) {
        String user = hint != null ? hint : firstPresent(data,
                "username", "user_name", "user");
        String key  = requireField(data, "ssh_private_key", "private_key", "key", "ssh_key");
        String pass = firstPresent(data, "ssh_passphrase", "passphrase", "key_passphrase");
        return ResolvedCredential.builder(CredentialType.SSH_KEY)
                .userName(user)
                .sshPrivateKey(key)
                .sshPassphrase(pass)
                .build();
    }

    private static ResolvedCredential mapWindows(JsonNode data, String hint) {
        String user   = hint != null ? hint : requireField(data, "username", "user_name", "user");
        String pass   = requireField(data, "password", "pass", "secret");
        String domain = firstPresent(data, "windows_domain", "domain", "ntlm_domain");
        return ResolvedCredential.builder(CredentialType.WINDOWS_NTLM)
                .userName(user)
                .password(pass)
                .windowsDomain(domain)
                .build();
    }

    private static ResolvedCredential mapApiKey(JsonNode data) {
        String token = requireField(data,
                "api_key", "token", "access_token", "bearer_token",
                "secret_token", "password", "secret");
        String user  = firstPresent(data, "username", "user_name", "user", "client_id");
        return ResolvedCredential.builder(CredentialType.API_KEY_BEARER)
                .userName(user)
                .apiKey(token)
                .build();
    }

    private static ResolvedCredential mapAzureServicePrincipal(JsonNode data) {
        String clientId     = requireField(data, "client_id", "application_id", "app_id");
        String clientSecret = requireField(data, "client_secret", "secret", "password");
        String tenantId     = firstPresent(data, "tenant_id", "directory_id", "azure_tenant");
        return ResolvedCredential.builder(CredentialType.AZURE_SERVICE_PRINCIPAL)
                .userName(clientId)
                .password(clientSecret)
                .tenantId(tenantId)
                .build();
    }

    // ── Field resolution helpers ──────────────────────────────────────────────

    /** Return value of first key found; null if none found. */
    static String firstPresent(JsonNode data, String... keys) {
        for (String key : keys) {
            JsonNode n = data.get(key);
            if (n != null && !n.isNull() && !n.asText().isEmpty()) {
                return n.asText();
            }
        }
        return null;
    }

    /** Return value of first key found; throw if none found. */
    static String requireField(JsonNode data, String... keys) {
        String v = firstPresent(data, keys);
        if (v == null) {
            throw new CredentialResolverException(ErrorCode.MISSING_SECRET_FIELD,
                    "None of the expected fields found in vault secret: "
                            + String.join(", ", keys));
        }
        return v;
    }
}
