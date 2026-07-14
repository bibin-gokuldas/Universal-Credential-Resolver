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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AWS Secrets Manager provider.
 *
 * <h3>credential_id</h3>
 * The AWS secret name or full ARN:
 * <ul>
 *   <li>{@code prod/linux/root-credentials}</li>
 *   <li>{@code arn:aws:secretsmanager:ap-southeast-1:123456789:secret:prod/linux/root}</li>
 * </ul>
 *
 * <h3>Authentication modes</h3>
 * <ul>
 *   <li>AWS_IAM_ROLE (recommended) — uses IMDSv2 to obtain temporary credentials
 *       from the EC2 instance role assigned to the MID Server host</li>
 *   <li>STATIC_TOKEN — uses {@code vault.token} as a colon-separated
 *       {@code ACCESS_KEY_ID:SECRET_ACCESS_KEY} string</li>
 * </ul>
 *
 * <h3>API</h3>
 * AWS Secrets Manager REST API (Secrets Manager Actions via HTTP):
 * <pre>
 *   POST https://secretsmanager.{region}.amazonaws.com/
 *   X-Amz-Target: secretsmanager.GetSecretValue
 *   Body: {"SecretId":"..."}
 * </pre>
 * This avoids the AWS SDK dependency (keeping the JAR lean on the MID Server).
 * SigV4 signing is implemented inline.
 */
public class AwsSecretsManagerProvider implements VaultProvider {

    private static final Logger LOG = LoggerFactory.getLogger(AwsSecretsManagerProvider.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    // IMDSv2 endpoints
    private static final String IMDS_TOKEN_URL =
            "http://169.254.169.254/latest/api/token";
    private static final String IMDS_CREDS_URL =
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/";

    private static final String SERVICE = "secretsmanager";

    private final ConcurrentHashMap<String, CachedAwsCreds> credsCache =
            new ConcurrentHashMap<>();

    @Override
    public String providerName() { return "AWS Secrets Manager"; }

    @Override
    public ResolvedCredential resolve(VaultConfig cfg) {
        AwsCredentials awsCreds = acquireAwsCredentials(cfg);
        String region   = cfg.getAwsRegion();
        String endpoint = "https://secretsmanager." + region + ".amazonaws.com/";

        String reqBody = "{\"SecretId\":\"" + cfg.getCredentialId() + "\"}";

        // SigV4-sign the request
        String[] signedResult = signRequest(awsCreds, region, endpoint, reqBody);
        String authHeader     = signedResult[0];
        String dateHeader     = signedResult[1];
        String dateTimeHeader = signedResult[2];

        OkHttpClient client = VaultHttpClient.build(cfg);
        Headers headers = new Headers.Builder()
                .add("X-Amz-Target", "secretsmanager.GetSecretValue")
                .add("Content-Type", "application/x-amz-json-1.1")
                .add("Authorization", authHeader)
                .add("X-Amz-Date", dateTimeHeader)
                .add("X-Amz-Date-Short", dateHeader)
                .addAll(awsCreds.sessionToken != null
                        ? Headers.of("X-Amz-Security-Token", awsCreds.sessionToken)
                        : Headers.of())
                .build();

        LOG.debug("[AWS-SM] Fetching secret: {}", cfg.getCredentialId());
        String respBody = VaultHttpClient.post(client, endpoint, reqBody, headers, cfg);

        return parseAwsResponse(respBody, cfg);
    }

    // ── AWS credential acquisition ────────────────────────────────────────────

    private AwsCredentials acquireAwsCredentials(VaultConfig cfg) {
        if (cfg.getAuthMethod() == AuthMethod.STATIC_TOKEN) {
            // Format: ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]
            String raw = cfg.getHcStaticToken();
            if (raw == null) {
                throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                        "AWS STATIC_TOKEN auth requires vault.token = "
                        + "ACCESS_KEY_ID:SECRET_ACCESS_KEY");
            }
            String[] parts = raw.split(":", 3);
            return new AwsCredentials(parts[0], parts[1],
                    parts.length > 2 ? parts[2] : null, Long.MAX_VALUE);
        }

        if (cfg.getAuthMethod() == AuthMethod.AWS_IAM_ROLE) {
            return fetchImdsv2Credentials(cfg);
        }

        throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                "AWS Secrets Manager supports AWS_IAM_ROLE or STATIC_TOKEN. Got: "
                + cfg.getAuthMethod());
    }

    private AwsCredentials fetchImdsv2Credentials(VaultConfig cfg) {
        String cacheKey = "imds";
        CachedAwsCreds cached = credsCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            LOG.debug("[AWS-SM] Reusing cached IMDSv2 credentials");
            return cached.creds;
        }

        try {
            // Step 1: Get IMDSv2 session token (TTL 21600s = 6h)
            OkHttpClient imdsClient = new OkHttpClient.Builder()
                    .connectTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                    .readTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                    .build();

            Headers putHeaders = new Headers.Builder()
                    .add("X-aws-ec2-metadata-token-ttl-seconds", "21600")
                    .build();
            String imdsToken = VaultHttpClient.post(imdsClient, IMDS_TOKEN_URL,
                    "", putHeaders, cfg);
            if (imdsToken == null || imdsToken.isBlank()) {
                throw new CredentialResolverException(ErrorCode.VAULT_AUTH_FAILED,
                        "IMDSv2 token request returned empty response");
            }

            // Step 2: Discover instance role name
            Headers getHeaders = new Headers.Builder()
                    .add("X-aws-ec2-metadata-token", imdsToken.trim())
                    .build();
            String roleName = VaultHttpClient.get(imdsClient, IMDS_CREDS_URL,
                    getHeaders, cfg).trim();

            // Step 3: Fetch temporary credentials for that role
            String credJson = VaultHttpClient.get(imdsClient,
                    IMDS_CREDS_URL + roleName, getHeaders, cfg);
            JsonNode root = JSON.readTree(credJson);

            String accessKey    = root.path("AccessKeyId").asText();
            String secretKey    = root.path("SecretAccessKey").asText();
            String sessionToken = root.path("Token").asText(null);
            // Parse expiration ("2026-07-13T12:00:00Z") — use 80% of TTL
            long expiresAt = System.currentTimeMillis() + (3600L * 800L); // default ~48min

            AwsCredentials creds = new AwsCredentials(accessKey, secretKey,
                    sessionToken, expiresAt);
            credsCache.put(cacheKey, new CachedAwsCreds(creds, expiresAt));
            LOG.info("[AWS-SM] IMDSv2 credentials obtained for role: {}", roleName);
            return creds;

        } catch (CredentialResolverException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.VAULT_AUTH_FAILED,
                    "IMDSv2 credential fetch failed", e);
        }
    }

    // ── SigV4 signing (inline, no AWS SDK) ───────────────────────────────────

    /**
     * Minimal AWS SigV4 signing for POST requests to Secrets Manager.
     * Returns [authorizationHeader, dateShort, dateTimeLong].
     */
    private String[] signRequest(AwsCredentials creds, String region,
                                  String endpoint, String body) {
        try {
            ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
            String dateTime         = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
            String dateShort        = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
            String host             = "secretsmanager." + region + ".amazonaws.com";
            String contentType      = "application/x-amz-json-1.1";
            String amzTarget        = "secretsmanager.GetSecretValue";

            // Canonical headers (must be sorted)
            String canonicalHeaders = "content-type:" + contentType + "\n"
                    + "host:" + host + "\n"
                    + "x-amz-date:" + dateTime + "\n"
                    + "x-amz-target:" + amzTarget + "\n";
            String signedHeaders    = "content-type;host;x-amz-date;x-amz-target";

            // Hash body
            String bodyHash = sha256Hex(body.getBytes(StandardCharsets.UTF_8));

            // Canonical request
            String canonicalRequest = "POST\n/\n\n"
                    + canonicalHeaders + "\n"
                    + signedHeaders + "\n"
                    + bodyHash;

            // String to sign
            String credentialScope  = dateShort + "/" + region + "/" + SERVICE + "/aws4_request";
            String stringToSign     = "AWS4-HMAC-SHA256\n" + dateTime + "\n"
                    + credentialScope + "\n"
                    + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

            // Signing key
            byte[] signingKey = hmacSha256(
                    hmacSha256(
                            hmacSha256(
                                    hmacSha256(
                                            ("AWS4" + creds.secretKey)
                                                    .getBytes(StandardCharsets.UTF_8),
                                            dateShort),
                                    region),
                    SERVICE),
            "aws4_request");

            String signature = bytesToHex(hmacSha256(signingKey, stringToSign));

            String authHeader = "AWS4-HMAC-SHA256 Credential="
                    + creds.accessKey + "/" + credentialScope
                    + ", SignedHeaders=" + signedHeaders
                    + ", Signature=" + signature;

            return new String[]{authHeader, dateShort, dateTime};

        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                    "SigV4 signing failed", e);
        }
    }

    // ── Response parsing ──────────────────────────────────────────────────────

    private ResolvedCredential parseAwsResponse(String body, VaultConfig cfg) {
        try {
            JsonNode root = JSON.readTree(body);

            // AWS error shape: { "__type": "...", "message": "..." }
            JsonNode errType = root.get("__type");
            if (errType != null) {
                throw new CredentialResolverException(ErrorCode.SECRET_NOT_FOUND,
                        "AWS SM error: " + errType.asText()
                        + " — " + root.path("message").asText());
            }

            // SecretString (JSON) or SecretBinary
            String secretString = root.path("SecretString").asText();
            if (secretString.isEmpty()) {
                throw new CredentialResolverException(ErrorCode.MISSING_SECRET_FIELD,
                        "AWS SM SecretString is empty; SecretBinary not supported");
            }

            // If SecretString is JSON, parse as multi-field
            JsonNode dataNode;
            if (secretString.trim().startsWith("{")) {
                dataNode = JSON.readTree(secretString);
            } else {
                com.fasterxml.jackson.databind.node.ObjectNode single =
                        JSON.createObjectNode();
                single.put("password", secretString);
                single.put("api_key", secretString);
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
                    "Failed to parse AWS SM response", e);
        }
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    private static String sha256Hex(byte[] data) throws NoSuchAlgorithmException {
        return bytesToHex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    private static byte[] hmacSha256(byte[] key, String data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ── Inner types ───────────────────────────────────────────────────────────

    private static class AwsCredentials {
        final String accessKey, secretKey, sessionToken;
        final long expiresAtMs;
        AwsCredentials(String ak, String sk, String st, long exp) {
            this.accessKey = ak; this.secretKey = sk;
            this.sessionToken = st; this.expiresAtMs = exp;
        }
    }

    private static class CachedAwsCreds {
        final AwsCredentials creds; final long expiresAtMs;
        CachedAwsCreds(AwsCredentials c, long e) { this.creds = c; this.expiresAtMs = e; }
        boolean isExpired() {
            return System.currentTimeMillis() >= (expiresAtMs - 60_000L);
        }
    }
}
