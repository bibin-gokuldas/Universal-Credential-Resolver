package com.servicenow.mid.credentials.core;

import com.servicenow.mid.credentials.config.VaultConfig;
import com.servicenow.mid.credentials.model.ResolvedCredential;

/**
 * SPI contract implemented by every vault backend.
 *
 * <p>Implementations must be stateless with respect to credential data.
 * They may cache vault authentication tokens internally (e.g. Vault leases,
 * Azure access tokens) but MUST NOT cache resolved credential values.</p>
 *
 * <p>Thread safety: each provider is instantiated once per VaultProviderFactory
 * and MAY be called concurrently from multiple MID discovery threads.</p>
 */
public interface VaultProvider {

    /**
     * Resolve credentials for the given config.
     *
     * @param config fully-populated VaultConfig
     * @return resolved credential — never null
     * @throws CredentialResolverException on any vault communication,
     *         authentication, or data-mapping failure
     */
    ResolvedCredential resolve(VaultConfig config) throws CredentialResolverException;

    /**
     * Human-readable name used in logs and error messages.
     */
    String providerName();
}
