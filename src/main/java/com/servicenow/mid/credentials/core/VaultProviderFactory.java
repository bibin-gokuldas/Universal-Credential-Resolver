package com.servicenow.mid.credentials.core;

import com.servicenow.mid.credentials.config.VaultConfig;
import com.servicenow.mid.credentials.providers.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumMap;
import java.util.Map;

/**
 * Factory and dispatcher for {@link VaultProvider} implementations.
 *
 * <p>Providers are singletons within the factory instance. The factory
 * itself is instantiated once by {@link UniversalCredentialResolver} and
 * reused across all resolve() calls to preserve token caches.</p>
 */
public class VaultProviderFactory {

    private static final Logger LOG = LoggerFactory.getLogger(VaultProviderFactory.class);

    private final Map<VaultConfig.VaultType, VaultProvider> registry =
            new EnumMap<>(VaultConfig.VaultType.class);

    public VaultProviderFactory() {
        register(VaultConfig.VaultType.HASHICORP,
                new com.servicenow.mid.credentials.providers.HashiCorpVaultProvider());
        register(VaultConfig.VaultType.CYBERARK,
                new com.servicenow.mid.credentials.providers.CyberArkCCPProvider());
        register(VaultConfig.VaultType.AZURE_KEY_VAULT,
                new com.servicenow.mid.credentials.providers.AzureKeyVaultProvider());
        register(VaultConfig.VaultType.AWS_SECRETS_MANAGER,
                new com.servicenow.mid.credentials.providers.AwsSecretsManagerProvider());
        register(VaultConfig.VaultType.DELINEA,
                new com.servicenow.mid.credentials.providers.DelineaSecretServerProvider());
    }

    public void register(VaultConfig.VaultType type, VaultProvider provider) {
        registry.put(type, provider);
        LOG.info("Registered vault provider: {} → {}", type, provider.providerName());
    }

    public VaultProvider getProvider(VaultConfig.VaultType type) {
        VaultProvider p = registry.get(type);
        if (p == null) {
            throw new CredentialResolverException(
                    CredentialResolverException.ErrorCode.CONFIGURATION_ERROR,
                    "No provider registered for vault type: " + type);
        }
        return p;
    }
}
