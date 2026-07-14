package com.servicenow.mid.credentials.providers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.servicenow.mid.credentials.config.VaultConfig;
import com.servicenow.mid.credentials.config.VaultConfig.AuthMethod;
import com.servicenow.mid.credentials.core.CredentialResolverException;
import com.servicenow.mid.credentials.core.CredentialResolverException.ErrorCode;
import com.servicenow.mid.credentials.core.VaultProvider;
import com.servicenow.mid.credentials.model.ResolvedCredential;
import com.servicenow.mid.credentials.util.CredentialMapper;
import com.servicenow.mid.credentials.util.VaultHttpClient;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Azure Key Vault (AKV) secret provider.
 *
 * <h3>credential_id</h3>
 * The name of the secret in AKV, e.g. {@code prod-linux-root-password}.
 * To pin a specific version, append a slash and the version ID:
 * {@code prod-linux-root-password/abc123def456...}
 *
 * <h3>Vault URL</h3>
 * Set {@code mid.external_credentials.vault.url} to the AKV vault URI:
 * {@code https://my-vault.vault.azure.net}
 *
 * <h3>Authentication modes</h3>
 * <ul>
 *   <li>AZURE_MANAGED_IDENTITY — IMDS endpoint on the MID Server host VM
 *       ({@code http://169.254.169.254/metadata/identity/oauth2/token})</li>
 *   <li>STATIC_TOKEN (via SP) — exchange client_id + client_secret for a
 *       bearer token using the Azure AD token endpoint</li>
 *   <li>MTLS — certificate-based SP auth (client assertion flow)</li>
 * </ul>
 *
 * <h3>Multi-value secrets</h3>
 * AKV stores secrets as a single string value. For structured credentials,
 * store a JSON string in the AKV secret and this provider will detect and
 * parse it automatically.
 */
public class AzureKeyVaultProvider implements VaultProvider {

    private static final Logger LOG = LoggerFactory.getLogger(AzureKeyVaultProvider.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String IMDS_URL =
            "http://169.254.169.254/metadata/identity/oauth2/token"
            + "?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net";
    private static final String AKV_API_VERSION = "7.4";

    private final ConcurrentHashMap<String, CachedToken> tokenCache = new ConcurrentHashMap<>();

    @Override
    public String providerName() { return "Azure Key Vault"; }

    @Override
    public ResolvedCredential resolve(VaultConfig cfg) {
        String accessToken = acquireAccessToken(cfg);

        // Build AKV secret URL
        String secretUrl = buildSecretUrl(cfg);
        LOG.debug("[AzureKV] Fetching secret: {}", secretUrl);

        OkHttpClient client = VaultHttpClient.build(cfg);
        Headers headers = new Headers.Builder()
                .add("Authorization", "Bearer " + accessToken)
                .add("Content-Type", "application/json")
                .build();

        String respBody = VaultHttpClient.get(client, secretUrl, headers, cfg);
        return parseAkvResponse(respBody, cfg);
    }

    // ── Token acquisition ─────────────────────────────────────────────────────

    private String acquireAccessToken(VaultConfig cfg) {
        String cacheKey = cfg.getVaultUrl() + "|" + cfg.getAuthMethod();
        CachedToken cached = tokenCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            LOG.debug("[AzureKV] Reusing cached access token");
            return cached.token;
        }

        String token;
        long   expiresAt;

        if (cfg.getAuthMethod() == AuthMethod.AZURE_MANAGED_IDENTITY) {
            TokenResponse tr = fetchManagedIdentityToken(cfg);
            token     = tr.token;
            expiresAt = tr.expiresAt;
        } else if (cfg.getAuthMethod() == AuthMethod.STATIC_TOKEN) {
            // Service Principal: client_id + client_secret → access token
            TokenResponse tr = fetchSpToken(cfg);
            token     = tr.token;
            expiresAt = tr.expiresAt;
        } else {
            throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                    "Azure Key Vault supports AZURE_MANAGED_IDENTITY or STATIC_TOKEN auth. Got: "
                    + cfg.getAuthMethod());
        }

        tokenCache.put(cacheKey, new CachedToken(token, expiresAt));
        return token;
    }

    private TokenResponse fetchManagedIdentityToken(VaultConfig cfg) {
        LOG.debug("[AzureKV] Acquiring token via Managed Identity (IMDS)");
        // IMDS does not use the standard VaultHttpClient TLS setup —
        // it is a plain HTTP link-local endpoint
        OkHttpClient imdsClient = new OkHttpClient.Builder()
                .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                .build();

        Headers imdsHeaders = new Headers.Builder()
                .add("Metadata", "true")
                .build();

        String resp = VaultHttpClient.get(imdsClient, IMDS_URL, imdsHeaders, cfg);
        return parseTokenResponse(resp);
    }

    private TokenResponse fetchSpToken(VaultConfig cfg) {
        LOG.debug("[AzureKV] Acquiring token via Service Principal");
        if (cfg.getAzureTenantId() == null || cfg.getAzureClientId() == null
                || cfg.getAzureClientSecret() == null) {
            throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                    "Azure SP auth requires azure.tenant_id, azure.client_id, "
                    + "azure.client_secret MID properties");
        }

        String tokenUrl = "https://login.microsoftonline.com/"
                + cfg.getAzureTenantId() + "/oauth2/v2.0/token";

        String body;
        try {
            body = "grant_type=client_credentials"
                    + "&client_id=" + encode(cfg.getAzureClientId())
                    + "&client_secret=" + encode(cfg.getAzureClientSecret())
                    + "&scope=" + encode("https://vault.azure.net/.default");
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                    "Failed to encode SP token request body", e);
        }

        OkHttpClient client = VaultHttpClient.build(cfg);
        Headers headers = new Headers.Builder()
                .add("Content-Type", "application/x-www-form-urlencoded")
                .build();

        // Post as form-encoded (OkHttp POST with text body)
        String resp = VaultHttpClient.post(client, tokenUrl, body,
                new Headers.Builder()
                        .add("Content-Type", "application/x-www-form-urlencoded")
                        .build(), cfg);
        return parseTokenResponse(resp);
    }

    private TokenResponse parseTokenResponse(String body) {
        try {
            JsonNode root     = JSON.readTree(body);
            String   token    = root.path("access_token").asText();
            long     expiresIn = root.path("expires_in").asLong(3600L);
            if (token.isEmpty()) {
                throw new CredentialResolverException(ErrorCode.VAULT_AUTH_FAILED,
                        "Azure token response missing access_token");
            }
            long expiresAt = System.currentTimeMillis() + (expiresIn * 900L); // 90% of TTL
            return new TokenResponse(token, expiresAt);
        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.PARSE_ERROR,
                    "Failed to parse Azure token response", e);
        }
    }

    // ── URL + parsing ─────────────────────────────────────────────────────────

    private String buildSecretUrl(VaultConfig cfg) {
        String base     = cfg.getVaultUrl().replaceAll("/$", "");
        String secretId = cfg.getCredentialId().replaceAll("^/", "");
        return base + "/secrets/" + secretId + "?api-version=" + AKV_API_VERSION;
    }

    private ResolvedCredential parseAkvResponse(String body, VaultConfig cfg) {
        try {
            JsonNode root  = JSON.readTree(body);

            // AKV error shape: { "error": { "code": "...", "message": "..." } }
            JsonNode error = root.path("error");
            if (!error.isMissingNode() && !error.isNull()) {
                throw new CredentialResolverException(ErrorCode.SECRET_NOT_FOUND,
                        "AKV error: " + error.path("code").asText()
                        + " — " + error.path("message").asText());
            }

            String value = root.path("value").asText();
            if (value.isEmpty()) {
                throw new CredentialResolverException(ErrorCode.MISSING_SECRET_FIELD,
                        "AKV secret 'value' field is empty");
            }

            // If the secret value is a JSON object, parse it for multi-field credentials
            JsonNode dataNode;
            if (value.trim().startsWith("{")) {
                dataNode = JSON.readTree(value);
            } else {
                // Single-value secret — treat as password or API key
                com.fasterxml.jackson.databind.node.ObjectNode single =
                        JSON.createObjectNode();
                single.put("password", value);
                single.put("api_key", value);
                if (cfg.getUsernameHint() != null) {
                    single.put("username", cfg.getUsernameHint());
                }
                dataNode = single;
            }

            return CredentialMapper.map(dataNode, cfg.getCredentialType(),
                    cfg.getUsernameHint());

        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.PARSE_ERROR,
                    "Failed to parse AKV response", e);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String encode(String v) throws UnsupportedEncodingException {
        return URLEncoder.encode(v, StandardCharsets.UTF_8.name());
    }

    private static class TokenResponse {
        final String token; final long expiresAt;
        TokenResponse(String t, long e) { this.token = t; this.expiresAt = e; }
    }

    private static class CachedToken {
        final String token; final long expiresAtMs;
        CachedToken(String t, long e) { this.token = t; this.expiresAtMs = e; }
        boolean isExpired() { return System.currentTimeMillis() >= expiresAtMs; }
    }
}
