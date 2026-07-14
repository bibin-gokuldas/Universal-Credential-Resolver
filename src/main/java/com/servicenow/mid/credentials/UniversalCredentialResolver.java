package com.servicenow.mid.credentials;

import com.servicenow.mid.credentials.config.VaultConfig;
import com.servicenow.mid.credentials.core.CredentialResolverException;
import com.servicenow.mid.credentials.core.VaultProvider;
import com.servicenow.mid.credentials.core.VaultProviderFactory;
import com.servicenow.mid.credentials.model.ResolvedCredential;
import com.snc.discovery.CredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * ServiceNow Universal External Credential Resolver.
 *
 * <p>This is the entry point registered with the ServiceNow MID Server.
 * It implements the {@code IExternalCredential} SPI (surfaced as
 * {@code CredentialResolver} from {@code agent.jar}) and routes each
 * credential resolution request to the appropriate vault backend.</p>
 *
 * <h2>Registration in ServiceNow</h2>
 * <ol>
 *   <li>Navigate to <b>Discovery → Credential Stores → External Credential Stores</b></li>
 *   <li>Create a new record:
 *     <ul>
 *       <li><b>Name:</b> Universal Credential Resolver</li>
 *       <li><b>Java class name:</b> {@code com.servicenow.mid.credentials.UniversalCredentialResolver}</li>
 *       <li><b>JAR file:</b> Upload {@code sn-universal-credential-resolver-1.0.0.jar}</li>
 *     </ul>
 *   </li>
 *   <li>The JAR is auto-distributed to all MID Servers in the organisation.</li>
 * </ol>
 *
 * <h2>Credential record configuration</h2>
 * <pre>
 *   Type:           &lt;any supported SN type&gt;
 *   Credential ID:  &lt;vault-specific secret path/name&gt;
 *   External store: Universal Credential Resolver (above)
 * </pre>
 *
 * <h2>MID Server system properties (agent/config.xml or SN UI)</h2>
 * <pre>
 *   mid.external_credentials.vault.type         = hashicorp | cyberark | azure_kv | aws_sm | delinea
 *   mid.external_credentials.vault.url          = https://vault.corp.example.com
 *   mid.external_credentials.vault.auth_method  = token | approle | azure_mi | aws_iam | mtls
 *   [... see VaultConfig Javadoc for full property list ...]
 * </pre>
 *
 * <h2>Returned map keys (consumed by SN Discovery)</h2>
 * <pre>
 *   user_name        — all types
 *   password         — USERNAME_PASSWORD, WINDOWS_NTLM, AZURE_SP
 *   ssh_private_key  — SSH_KEY
 *   ssh_passphrase   — SSH_KEY (optional)
 *   windows_domain   — WINDOWS_NTLM (optional)
 *   api_key          — API_KEY_BEARER
 *   tenant_id        — AZURE_SERVICE_PRINCIPAL (optional)
 * </pre>
 */
public class UniversalCredentialResolver implements CredentialResolver {

    private static final Logger LOG =
            LoggerFactory.getLogger(UniversalCredentialResolver.class);

    // Singleton factory — preserves token caches across resolve() calls
    private static final VaultProviderFactory FACTORY = new VaultProviderFactory();

    /**
     * Main SPI entry point called by the MID Server for every Discovery
     * credential resolution request.
     *
     * @param credentialParams  map containing credential record fields from SN:
     *                          {@code id}, {@code type}, {@code user_name}, etc.
     * @param midParameters     map of MID Server system properties
     *                          (mid.external_credentials.*)
     * @return map of credential key-value pairs consumed by Discovery probes
     */
    @Override
    public Map<String, String> resolve(Map<String, String> credentialParams,
                                        Map<String, String> midParameters) {

        String credentialId = credentialParams.getOrDefault("id",
                credentialParams.get("credential_id"));
        String credType     = credentialParams.getOrDefault("type", "unknown");

        LOG.info("UniversalCredentialResolver.resolve() called: id={}, type={}",
                credentialId, credType);

        try {
            // Merge: credential attributes + MID properties → unified config map
            Map<String, String> credAttrs = new HashMap<>(credentialParams);
            credAttrs.putIfAbsent("credential_id",
                    credentialId != null ? credentialId : "");

            VaultConfig       cfg      = VaultConfig.from(midParameters, credAttrs);
            VaultProvider     provider = FACTORY.getProvider(cfg.getVaultType());

            LOG.debug("Routing to provider: {} | credential: {}",
                    provider.providerName(), cfg.getCredentialId());

            ResolvedCredential resolved = provider.resolve(cfg);

            Map<String, String> result = toSnMap(resolved);
            LOG.info("Credential resolved successfully: provider={}, type={}",
                    provider.providerName(), resolved.getCredentialType());

            return result;

        } catch (CredentialResolverException e) {
            LOG.error("Credential resolution failed [{}]: {}",
                    e.getErrorCode(), e.getMessage(), e);
            // ServiceNow expects an exception to signal failure (not an empty map)
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error in UniversalCredentialResolver: {}", e.getMessage(), e);
            throw new CredentialResolverException(
                    CredentialResolverException.ErrorCode.UNKNOWN,
                    "Unexpected resolver error: " + e.getMessage(), e);
        }
    }

    // ── Map ResolvedCredential → SN expected key names ────────────────────────

    private static Map<String, String> toSnMap(ResolvedCredential r) {
        Map<String, String> map = new HashMap<>();

        putIfNotNull(map, "user_name",        r.getUserName());
        putIfNotNull(map, "password",         r.getPassword());
        putIfNotNull(map, "ssh_private_key",  r.getSshPrivateKey());
        putIfNotNull(map, "ssh_passphrase",   r.getSshPassphrase());
        putIfNotNull(map, "windows_domain",   r.getWindowsDomain());
        putIfNotNull(map, "pki_certificate",  r.getPkiCertificate());
        putIfNotNull(map, "pki_key",          r.getPkiKey());
        putIfNotNull(map, "api_key",          r.getApiKey());
        putIfNotNull(map, "tenant_id",        r.getTenantId());

        // SN also uses "username" as an alias in some probes
        if (r.getUserName() != null) {
            map.put("username", r.getUserName());
        }

        return map;
    }

    private static void putIfNotNull(Map<String, String> map, String key, String value) {
        if (value != null && !value.isEmpty()) {
            map.put(key, value);
        }
    }
}
