package com.servicenow.mid.credentials.util;

import com.servicenow.mid.credentials.config.VaultConfig;
import com.servicenow.mid.credentials.core.CredentialResolverException;
import com.servicenow.mid.credentials.core.CredentialResolverException.ErrorCode;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Factory that builds a configured OkHttpClient for vault communication.
 *
 * <p>Handles:</p>
 * <ul>
 *   <li>Connection + read timeouts from {@link VaultConfig}</li>
 *   <li>mTLS (client certificate + key) when auth_method=MTLS</li>
 *   <li>Custom CA trust anchor (optional)</li>
 *   <li>Retry-safe POST (disabled for vault writes, enabled for GETs)</li>
 * </ul>
 */
public class VaultHttpClient {

    private static final Logger LOG = LoggerFactory.getLogger(VaultHttpClient.class);

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private VaultHttpClient() {}

    /**
     * Build a singleton-safe OkHttpClient for the given config.
     * Callers should cache the returned client and share it across requests.
     */
    public static OkHttpClient build(VaultConfig cfg) {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(cfg.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .readTimeout(cfg.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .writeTimeout(cfg.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(true);

        // ── mTLS / Custom CA ─────────────────────────────────────────────────
        if (cfg.getAuthMethod() == com.servicenow.mid.credentials.config.VaultConfig.AuthMethod.MTLS
                || cfg.getCaCertPath() != null
                || cfg.getMtlsCertPath() != null) {
            applySsl(builder, cfg);
        }

        return builder.build();
    }

    /**
     * Execute a GET request with retry logic.
     */
    public static String get(OkHttpClient client, String url,
                              Headers headers, VaultConfig cfg) {
        return executeWithRetry(client,
                new Request.Builder().url(url).headers(headers).get().build(),
                cfg.getRetryCount());
    }

    /**
     * Execute a POST request with JSON body, with retry logic.
     */
    public static String post(OkHttpClient client, String url,
                               String jsonBody, Headers headers, VaultConfig cfg) {
        RequestBody body = RequestBody.create(jsonBody, JSON);
        return executeWithRetry(client,
                new Request.Builder().url(url).headers(headers).post(body).build(),
                cfg.getRetryCount());
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static String executeWithRetry(OkHttpClient client,
                                            Request request, int maxRetries) {
        int attempt = 0;
        while (true) {
            attempt++;
            try (Response response = client.newCall(request).execute()) {
                int code = response.code();
                String responseBody = response.body() != null
                        ? response.body().string() : "";

                if (code == 200 || code == 204) {
                    return responseBody;
                }
                if (code == 401 || code == 403) {
                    throw new CredentialResolverException(ErrorCode.VAULT_AUTH_FAILED,
                            "HTTP " + code + " from vault: " + url(request));
                }
                if (code == 404) {
                    throw new CredentialResolverException(ErrorCode.SECRET_NOT_FOUND,
                            "Secret not found (HTTP 404): " + url(request));
                }
                if (code >= 500 && attempt <= maxRetries) {
                    LOG.warn("Vault HTTP {} on attempt {}/{}; retrying in {}ms",
                            code, attempt, maxRetries, backoffMs(attempt));
                    sleep(backoffMs(attempt));
                    continue;
                }
                throw new CredentialResolverException(ErrorCode.VAULT_UNAVAILABLE,
                        "Vault returned HTTP " + code + ": " + responseBody);

            } catch (CredentialResolverException e) {
                throw e; // propagate typed exceptions directly
            } catch (IOException e) {
                if (attempt <= maxRetries) {
                    LOG.warn("IO error on attempt {}/{}: {}; retrying",
                            attempt, maxRetries, e.getMessage());
                    sleep(backoffMs(attempt));
                } else {
                    throw new CredentialResolverException(ErrorCode.VAULT_UNAVAILABLE,
                            "Vault unreachable after " + maxRetries + " attempts", e);
                }
            }
        }
    }

    private static void applySsl(OkHttpClient.Builder builder, VaultConfig cfg) {
        try {
            TrustManager[] trustManagers = buildTrustManagers(cfg);
            KeyManager[]   keyManagers   = buildKeyManagers(cfg);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, new SecureRandom());

            SSLSocketFactory ssf = sslContext.getSocketFactory();
            X509TrustManager trustManager = (X509TrustManager) trustManagers[0];

            builder.sslSocketFactory(ssf, trustManager);
        } catch (Exception e) {
            throw new CredentialResolverException(ErrorCode.CONFIGURATION_ERROR,
                    "SSL/mTLS configuration failed: " + e.getMessage(), e);
        }
    }

    private static TrustManager[] buildTrustManagers(VaultConfig cfg) throws Exception {
        if (cfg.getCaCertPath() != null) {
            // Load custom CA cert
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            try (InputStream is = Files.newInputStream(Paths.get(cfg.getCaCertPath()))) {
                X509Certificate caCert = (X509Certificate)
                        CertificateFactory.getInstance("X.509").generateCertificate(is);
                trustStore.setCertificateEntry("vault-ca", caCert);
            }
            TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            return tmf.getTrustManagers();
        }
        // Default JVM trust store
        TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        return tmf.getTrustManagers();
    }

    private static KeyManager[] buildKeyManagers(VaultConfig cfg) throws Exception {
        if (cfg.getMtlsCertPath() == null || cfg.getMtlsKeyPath() == null) {
            return null; // no client cert
        }
        // Load PEM cert
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        X509Certificate cert;
        try (InputStream is = Files.newInputStream(Paths.get(cfg.getMtlsCertPath()))) {
            cert = (X509Certificate) CertificateFactory
                    .getInstance("X.509").generateCertificate(is);
        }
        // Load PEM private key (PKCS8 DER)
        PrivateKey pk = loadPemPrivateKey(cfg.getMtlsKeyPath());

        ks.setKeyEntry("client-key", pk, new char[0],
                new java.security.cert.Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory
                .getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        return kmf.getKeyManagers();
    }

    static PrivateKey loadPemPrivateKey(String path) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

    private static long backoffMs(int attempt) {
        return Math.min(1000L * (1L << (attempt - 1)), 8000L); // 1s, 2s, 4s, 8s
    }

    private static String url(Request r) { return r.url().toString(); }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
