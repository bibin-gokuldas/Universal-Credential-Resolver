package com.servicenow.mid.credentials.providers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.servicenow.mid.credentials.config.VaultConfig;
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

/**
 * CyberArk Central Credential Provider (CCP) — AIMWebService REST API.
 *
 * <h3>Endpoint</h3>
 * <pre>
 *   GET {vault_url}/AIMWebService/api/Accounts
 *       ?AppID={appId}
 *       &Safe={safe}
 *       &Object={credential_id}
 *       [&UserName={username_hint}]
 * </pre>
 *
 * <h3>credential_id format (in SN credential record)</h3>
 * Compound identifier using {@code |} as separator:
 * <pre>
 *   {AppID}|{Safe}|{ObjectName}
 *   e.g.  MIDServer-App|Linux-Servers|root-prod-server01
 * </pre>
 *
 * <h3>Authentication modes</h3>
 * <ul>
 *   <li>MTLS          — Client certificate (most common CCP deployment)</li>
 *   <li>STATIC_TOKEN  — {@code Authorization: Bearer <token>} header</li>
 * </ul>
 *
 * <h3>Response mapping</h3>
 * CCP returns flat JSON: {@code {"UserName":"root","Content":"s3cr3t!",
 * "Address":"server01","Safe":"Linux-Servers",...}}
 */
public class CyberArkCCPProvider implements VaultProvider {

    private static final Logger LOG = LoggerFactory.getLogger(CyberArkCCPProvider.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public String providerName() { return "CyberArk CCP"; }

    @Override
    public ResolvedCredential resolve(VaultConfig cfg) {

        // Parse compound credential ID: AppID|Safe|ObjectName
        String[] parts = cfg.getCredentialId().split("\\|", 3);
        if (parts.length < 3) {
            throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                    "CyberArk credential_id must be in format AppID|Safe|ObjectName, got: "
                    + cfg.getCredentialId());
        }
        String appId      = parts[0].trim();
        String safe       = parts[1].trim();
        String objectName = parts[2].trim();

        // Build query URL
        String url = buildUrl(cfg.getVaultUrl(), appId, safe, objectName,
                cfg.getUsernameHint());
        LOG.debug("[CyberArk] Fetching: {}", url);

        // Build headers
        Headers.Builder hb = new Headers.Builder()
                .add("Content-Type", "application/json")
                .add("Accept", "application/json");

        if (cfg.getAuthMethod() == VaultConfig.AuthMethod.STATIC_TOKEN) {
            if (cfg.getHcStaticToken() == null) {
                throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                        "CyberArk auth_method=token requires vault.token MID property");
            }
            hb.add("Authorization", "Bearer " + cfg.getHcStaticToken());
        }
        // mTLS auth: certificate in OkHttpClient handles it automatically

        OkHttpClient client  = VaultHttpClient.build(cfg);
        String       respBody = VaultHttpClient.get(client, url, hb.build(), cfg);

        return parseCCPResponse(respBody, cfg);
    }

    // ── URL builder ───────────────────────────────────────────────────────────

    private String buildUrl(String baseUrl, String appId, String safe,
                             String objectName, String userNameHint) {
        StringBuilder sb = new StringBuilder(
                baseUrl.replaceAll("/$", ""))
                .append("/AIMWebService/api/Accounts?")
                .append("AppID=").append(encode(appId))
                .append("&Safe=").append(encode(safe))
                .append("&Object=").append(encode(objectName));

        if (userNameHint != null && !userNameHint.isEmpty()) {
            sb.append("&UserName=").append(encode(userNameHint));
        }
        return sb.toString();
    }

    private static String encode(String v) {
        try {
            return URLEncoder.encode(v, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            return v; // UTF-8 always available
        }
    }

    // ── Response parsing ──────────────────────────────────────────────────────

    /**
     * CyberArk CCP returns a flat JSON object — not nested like HashiCorp.
     * We normalise it into a format CredentialMapper understands by
     * aliasing CCP field names to standard keys.
     */
    private ResolvedCredential parseCCPResponse(String body, VaultConfig cfg) {
        try {
            JsonNode root = JSON.readTree(body);

            // Check for CyberArk error responses
            JsonNode errCode = root.get("ErrorCode");
            if (errCode != null && !errCode.isNull()) {
                String msg = root.path("ErrorMsg").asText("unknown");
                throw new CredentialResolverException(ErrorCode.SECRET_NOT_FOUND,
                        "CyberArk CCP error " + errCode.asText() + ": " + msg);
            }

            // Normalise CyberArk fields → standard field names
            com.fasterxml.jackson.databind.node.ObjectNode normalised =
                    JSON.createObjectNode();

            copyField(root, normalised, "UserName",   "username");
            copyField(root, normalised, "Content",    "password");   // CCP: "Content" = password
            copyField(root, normalised, "Address",    "address");
            copyField(root, normalised, "PasswordChangeInProcess", "change_in_progress");

            // SSH key (if stored in CyberArk as custom property)
            copyField(root, normalised, "SSHKey",       "ssh_private_key");
            copyField(root, normalised, "SSHPassphrase","ssh_passphrase");

            // Windows domain
            copyField(root, normalised, "Domain",      "windows_domain");

            // API key (custom property name in CyberArk)
            copyField(root, normalised, "APIKey",      "api_key");
            copyField(root, normalised, "Token",       "token");

            // Azure SP
            copyField(root, normalised, "ClientID",    "client_id");
            copyField(root, normalised, "ClientSecret","client_secret");
            copyField(root, normalised, "TenantID",    "tenant_id");

            LOG.debug("[CyberArk] Resolved credential for object; type={}",
                    cfg.getCredentialType());

            return CredentialMapper.map(normalised, cfg.getCredentialType(),
                    cfg.getUsernameHint());

        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.PARSE_ERROR,
                    "Failed to parse CyberArk CCP response", e);
        }
    }

    private static void copyField(JsonNode src,
                                   com.fasterxml.jackson.databind.node.ObjectNode dst,
                                   String srcKey, String dstKey) {
        JsonNode v = src.get(srcKey);
        if (v != null && !v.isNull() && !v.asText().isEmpty()) {
            dst.put(dstKey, v.asText());
        }
    }
}
