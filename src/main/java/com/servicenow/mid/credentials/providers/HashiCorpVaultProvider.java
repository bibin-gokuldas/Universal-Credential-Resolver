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

import java.util.concurrent.ConcurrentHashMap;

/**
 * HashiCorp Vault KV provider (API v1 + v2).
 *
 * <h3>Authentication modes</h3>
 * <ul>
 *   <li>STATIC_TOKEN  — {@code X-Vault-Token} from MID property</li>
 *   <li>APPROLE       — exchange role_id + secret_id for a token (cached)</li>
 *   <li>MTLS          — TLS client cert presented; token read from Vault cert auth</li>
 * </ul>
 *
 * <h3>Secret path convention</h3>
 * <pre>
 *   KV v2:  GET {vault_url}/v1/{mount_path}/data/{credential_id}
 *   KV v1:  GET {vault_url}/v1/{mount_path}/{credential_id}
 * </pre>
 *
 * <h3>Namespace support (HashiCorp Enterprise)</h3>
 * Set {@code mid.external_credentials.vault.namespace} to e.g. {@code admin/team1}.
 */
public class HashiCorpVaultProvider implements VaultProvider {

    private static final Logger LOG = LoggerFactory.getLogger(HashiCorpVaultProvider.class);

    private static final ObjectMapper JSON = new ObjectMapper();

    // Per-instance token cache keyed by vaultUrl+roleId to support multi-vault deployments
    private final ConcurrentHashMap<String, CachedToken> tokenCache = new ConcurrentHashMap<>();

    @Override
    public String providerName() { return "HashiCorp Vault"; }

    @Override
    public ResolvedCredential resolve(VaultConfig cfg) {
        OkHttpClient client = VaultHttpClient.build(cfg);
        String token = acquireToken(client, cfg);

        // Build headers
        Headers.Builder hb = new Headers.Builder()
                .add("X-Vault-Token", token)
                .add("Content-Type", "application/json");
        if (cfg.getHcNamespace() != null) {
            hb.add("X-Vault-Namespace", cfg.getHcNamespace());
        }
        Headers headers = hb.build();

        // Build secret URL
        String url = buildSecretUrl(cfg);
        LOG.debug("[HashiCorp] Fetching secret: {}", url);

        String responseBody = VaultHttpClient.get(client, url, headers, cfg);
        JsonNode data = parseSecretData(responseBody, cfg.getHcKvVersion());

        return CredentialMapper.map(data, cfg.getCredentialType(), cfg.getUsernameHint());
    }

    // ── Token acquisition ─────────────────────────────────────────────────────

    private String acquireToken(OkHttpClient client, VaultConfig cfg) {
        AuthMethod method = cfg.getAuthMethod();

        if (method == AuthMethod.STATIC_TOKEN || method == AuthMethod.MTLS) {
            if (method == AuthMethod.STATIC_TOKEN) {
                if (cfg.getHcStaticToken() == null || cfg.getHcStaticToken().isEmpty()) {
                    throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                            "auth_method=token but vault.token property is not set");
                }
                return cfg.getHcStaticToken();
            }
            // mTLS: authenticate via cert auth endpoint
            return loginViaCert(client, cfg);
        }

        if (method == AuthMethod.APPROLE) {
            return loginViaAppRole(client, cfg);
        }

        throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                "HashiCorp Vault does not support auth_method: " + method
                + ". Use STATIC_TOKEN, APPROLE, or MTLS.");
    }

    private String loginViaAppRole(OkHttpClient client, VaultConfig cfg) {
        String cacheKey = cfg.getVaultUrl() + "|" + cfg.getHcRoleId();
        CachedToken cached = tokenCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            LOG.debug("[HashiCorp] Reusing cached AppRole token (expires in {}s)",
                    (cached.expiresAtMs - System.currentTimeMillis()) / 1000);
            return cached.token;
        }

        if (cfg.getHcRoleId() == null || cfg.getHcSecretId() == null) {
            throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                    "auth_method=approle requires vault.role_id and vault.secret_id properties");
        }

        String url = cfg.getVaultUrl() + "/v1/auth/approle/login";
        if (cfg.getHcNamespace() != null) {
            url = cfg.getVaultUrl() + "/v1/auth/approle/login"; // namespace via header
        }

        String body = String.format(
                "{\"role_id\":\"%s\",\"secret_id\":\"%s\"}",
                cfg.getHcRoleId(), cfg.getHcSecretId());

        Headers headers = new Headers.Builder()
                .add("Content-Type", "application/json")
                .add("X-Vault-Namespace", cfg.getHcNamespace() != null ? cfg.getHcNamespace() : "")
                .build();

        String resp = VaultHttpClient.post(client, url, body, headers, cfg);
        try {
            JsonNode root = JSON.readTree(resp);
            String token  = root.path("auth").path("client_token").asText();
            long   leaseSec = root.path("auth").path("lease_duration").asLong(3600L);
            if (token.isEmpty()) {
                throw new CredentialResolverException(ErrorCode.VAULT_AUTH_FAILED,
                        "AppRole login succeeded but response missing client_token");
            }
            // Cache with 80% of lease duration as safety margin
            tokenCache.put(cacheKey,
                    new CachedToken(token, System.currentTimeMillis() + (leaseSec * 800L)));
            LOG.info("[HashiCorp] AppRole login successful; token cached for ~{}s",
                    leaseSec * 4 / 5);
            return token;
        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.PARSE_ERROR,
                    "Failed to parse AppRole login response", e);
        }
    }

    private String loginViaCert(OkHttpClient client, VaultConfig cfg) {
        String cacheKey = cfg.getVaultUrl() + "|mtls";
        CachedToken cached = tokenCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.token;
        }

        String url  = cfg.getVaultUrl() + "/v1/auth/cert/login";
        Headers hdr = new Headers.Builder()
                .add("Content-Type", "application/json")
                .build();

        String resp = VaultHttpClient.post(client, url, "{}", hdr, cfg);
        try {
            JsonNode root   = JSON.readTree(resp);
            String   token  = root.path("auth").path("client_token").asText();
            long leaseSec   = root.path("auth").path("lease_duration").asLong(3600L);
            if (token.isEmpty()) {
                throw new CredentialResolverException(ErrorCode.VAULT_AUTH_FAILED,
                        "Cert auth login response missing client_token");
            }
            tokenCache.put(cacheKey,
                    new CachedToken(token, System.currentTimeMillis() + (leaseSec * 800L)));
            LOG.info("[HashiCorp] mTLS cert auth successful; token cached");
            return token;
        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.PARSE_ERROR,
                    "Failed to parse cert auth response", e);
        }
    }

    // ── URL + response parsing ────────────────────────────────────────────────

    private String buildSecretUrl(VaultConfig cfg) {
        String base  = cfg.getVaultUrl().replaceAll("/$", "");
        String mount = cfg.getHcMountPath().replaceAll("^/|/$", "");
        String path  = cfg.getCredentialId().replaceAll("^/", "");

        if (cfg.getHcKvVersion() == 2) {
            return base + "/v1/" + mount + "/data/" + path;
        } else {
            return base + "/v1/" + mount + "/" + path;
        }
    }

    private JsonNode parseSecretData(String body, int kvVersion) {
        try {
            JsonNode root = JSON.readTree(body);
            if (kvVersion == 2) {
                // KV v2: { data: { data: { key: value } } }
                JsonNode data = root.path("data").path("data");
                if (data.isMissingNode() || data.isNull()) {
                    throw new CredentialResolverException(ErrorCode.MISSING_SECRET_FIELD,
                            "KV v2 response missing data.data node");
                }
                return data;
            } else {
                // KV v1: { data: { key: value } }
                JsonNode data = root.path("data");
                if (data.isMissingNode() || data.isNull()) {
                    throw new CredentialResolverException(ErrorCode.MISSING_SECRET_FIELD,
                            "KV v1 response missing data node");
                }
                return data;
            }
        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.PARSE_ERROR,
                    "Failed to parse HashiCorp secret response", e);
        }
    }

    // ── Token cache ───────────────────────────────────────────────────────────

    private static class CachedToken {
        final String token;
        final long   expiresAtMs;
        CachedToken(String t, long exp) { this.token = t; this.expiresAtMs = exp; }
        boolean isExpired() { return System.currentTimeMillis() >= expiresAtMs; }
    }
}
