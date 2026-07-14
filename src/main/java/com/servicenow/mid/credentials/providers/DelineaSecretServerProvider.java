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
 * Delinea Secret Server (formerly Thycotic) REST API provider.
 *
 * <h3>credential_id</h3>
 * Numeric Secret ID as string, e.g. {@code 42}, or secret path:
 * {@code /MyFolder/LinuxServers/prod-root}
 *
 * <h3>Vault URL</h3>
 * {@code https://secretserver.corp.example.com/SecretServer}
 * or cloud: {@code https://example.secretservercloud.com}
 *
 * <h3>Authentication</h3>
 * <ul>
 *   <li>STATIC_TOKEN — {@code vault.role_id} = username,
 *       {@code vault.secret_id} = password for OAuth2 password grant</li>
 *   <li>MTLS — client certificate authentication</li>
 * </ul>
 *
 * <h3>API calls</h3>
 * <pre>
 *   POST /oauth2/token  → access_token
 *   GET  /api/v1/secrets/{id}  → secret metadata + field values
 * </pre>
 */
public class DelineaSecretServerProvider implements VaultProvider {

    private static final Logger LOG = LoggerFactory.getLogger(DelineaSecretServerProvider.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final ConcurrentHashMap<String, CachedToken> tokenCache = new ConcurrentHashMap<>();

    @Override
    public String providerName() { return "Delinea Secret Server"; }

    @Override
    public ResolvedCredential resolve(VaultConfig cfg) {
        String accessToken = acquireToken(cfg);
        String secretUrl   = buildSecretUrl(cfg);

        LOG.debug("[Delinea] Fetching secret: {}", secretUrl);

        OkHttpClient client = VaultHttpClient.build(cfg);
        Headers headers = new Headers.Builder()
                .add("Authorization", "Bearer " + accessToken)
                .add("Content-Type", "application/json")
                .build();

        String respBody = VaultHttpClient.get(client, secretUrl, headers, cfg);
        return parseDelineaResponse(respBody, cfg);
    }

    // ── Token acquisition ─────────────────────────────────────────────────────

    private String acquireToken(VaultConfig cfg) {
        if (cfg.getAuthMethod() == AuthMethod.MTLS) {
            // With mTLS, call the token endpoint with cert — server returns token
            return loginViaMtls(cfg);
        }

        if (cfg.getAuthMethod() == AuthMethod.STATIC_TOKEN
                || cfg.getAuthMethod() == AuthMethod.APPROLE) {
            // role_id = username, secret_id = password (OAuth2 password grant)
            return loginViaPassword(cfg);
        }

        throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                "Delinea supports STATIC_TOKEN (password grant) or MTLS. Got: "
                + cfg.getAuthMethod());
    }

    private String loginViaPassword(VaultConfig cfg) {
        String cacheKey = cfg.getVaultUrl() + "|" + cfg.getHcRoleId();
        CachedToken cached = tokenCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            LOG.debug("[Delinea] Reusing cached access token");
            return cached.token;
        }

        String username = cfg.getHcRoleId();
        String password = cfg.getHcSecretId();
        if (username == null || password == null) {
            throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                    "Delinea password grant requires vault.role_id (username) "
                    + "and vault.secret_id (password) MID properties");
        }

        String tokenUrl = cfg.getVaultUrl().replaceAll("/$", "") + "/oauth2/token";
        String body;
        try {
            body = "grant_type=password"
                    + "&username=" + encode(username)
                    + "&password=" + encode(password);
        } catch (UnsupportedEncodingException e) {
            body = "grant_type=password&username=" + username + "&password=" + password;
        }

        OkHttpClient client = VaultHttpClient.build(cfg);
        Headers hdr = new Headers.Builder()
                .add("Content-Type", "application/x-www-form-urlencoded")
                .build();

        String resp = VaultHttpClient.post(client, tokenUrl, body, hdr, cfg);
        return cacheAndReturn(resp, cacheKey);
    }

    private String loginViaMtls(VaultConfig cfg) {
        String cacheKey = cfg.getVaultUrl() + "|mtls";
        CachedToken cached = tokenCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.token;
        }

        String tokenUrl = cfg.getVaultUrl().replaceAll("/$", "") + "/oauth2/token";
        String body     = "grant_type=client_credentials";

        OkHttpClient client = VaultHttpClient.build(cfg);
        Headers hdr = new Headers.Builder()
                .add("Content-Type", "application/x-www-form-urlencoded")
                .build();

        String resp = VaultHttpClient.post(client, tokenUrl, body, hdr, cfg);
        return cacheAndReturn(resp, cacheKey);
    }

    private String cacheAndReturn(String resp, String cacheKey) {
        try {
            JsonNode root      = JSON.readTree(resp);
            String   token     = root.path("access_token").asText();
            long     expiresIn = root.path("expires_in").asLong(3600L);
            if (token.isEmpty()) {
                throw new CredentialResolverException(ErrorCode.VAULT_AUTH_FAILED,
                        "Delinea token response missing access_token. " +
                        "Check vault.role_id / vault.secret_id properties.");
            }
            long expiresAt = System.currentTimeMillis() + (expiresIn * 800L); // 80% TTL
            tokenCache.put(cacheKey, new CachedToken(token, expiresAt));
            LOG.info("[Delinea] Token acquired; cached for ~{}s", expiresIn * 4 / 5);
            return token;
        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.PARSE_ERROR,
                    "Failed to parse Delinea token response", e);
        }
    }

    // ── URL + parsing ─────────────────────────────────────────────────────────

    private String buildSecretUrl(VaultConfig cfg) {
        String base = cfg.getVaultUrl().replaceAll("/$", "");
        String id   = cfg.getCredentialId().trim();

        // If numeric ID, use /api/v1/secrets/{id}
        if (id.matches("\\d+")) {
            return base + "/api/v1/secrets/" + id;
        }
        // Otherwise search by path
        try {
            return base + "/api/v1/secrets?filter.searchText=" + encode(id)
                    + "&filter.isExactMatch=true";
        } catch (UnsupportedEncodingException e) {
            return base + "/api/v1/secrets?filter.searchText=" + id;
        }
    }

    /**
     * Delinea returns a Secret object with items[] array containing field values.
     * <pre>
     * {
     *   "id": 42,
     *   "name": "prod-root",
     *   "items": [
     *     {"fieldName": "Username", "itemValue": "root"},
     *     {"fieldName": "Password", "itemValue": "s3cr3t"},
     *     {"fieldName": "Domain",   "itemValue": "CORP"},
     *     {"fieldName": "Notes",    "itemValue": "..."}
     *   ]
     * }
     * </pre>
     */
    private ResolvedCredential parseDelineaResponse(String body, VaultConfig cfg) {
        try {
            JsonNode root = JSON.readTree(body);

            // Search result wraps in records[]
            if (root.has("records")) {
                JsonNode records = root.path("records");
                if (records.isEmpty()) {
                    throw new CredentialResolverException(ErrorCode.SECRET_NOT_FOUND,
                            "Delinea: no secret found matching: " + cfg.getCredentialId());
                }
                root = records.get(0); // take first match
            }

            // Flatten items[] into a standard key-value map
            com.fasterxml.jackson.databind.node.ObjectNode flat =
                    JSON.createObjectNode();
            JsonNode items = root.path("items");
            if (!items.isArray()) {
                throw new CredentialResolverException(ErrorCode.MISSING_SECRET_FIELD,
                        "Delinea secret 'items' array missing in response");
            }

            for (JsonNode item : items) {
                String fieldName = item.path("fieldName").asText("").toLowerCase();
                String value     = item.path("itemValue").asText("");
                if (value.isEmpty()) continue;

                // Normalise Delinea field names to standard keys
                switch (fieldName) {
                    case "username": flat.put("username", value);          break;
                    case "password": flat.put("password", value);          break;
                    case "domain":   flat.put("windows_domain", value);    break;
                    case "private key": case "ssh key":
                                     flat.put("ssh_private_key", value);   break;
                    case "passphrase": flat.put("ssh_passphrase", value);  break;
                    case "api key": case "token":
                                     flat.put("api_key", value);           break;
                    case "client id":  flat.put("client_id", value);       break;
                    case "client secret": flat.put("client_secret", value);break;
                    case "tenant id":  flat.put("tenant_id", value);       break;
                    default:
                        // Store any unknown fields verbatim (may be needed by CredentialMapper)
                        flat.put(fieldName.replace(" ", "_"), value);
                }
            }

            return CredentialMapper.map(flat, cfg.getCredentialType(), cfg.getUsernameHint());

        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.PARSE_ERROR,
                    "Failed to parse Delinea response", e);
        }
    }

    private static String encode(String v) throws UnsupportedEncodingException {
        return URLEncoder.encode(v, StandardCharsets.UTF_8.name());
    }

    private static class CachedToken {
        final String token; final long expiresAtMs;
        CachedToken(String t, long e) { this.token = t; this.expiresAtMs = e; }
        boolean isExpired() { return System.currentTimeMillis() >= expiresAtMs; }
    }
}
