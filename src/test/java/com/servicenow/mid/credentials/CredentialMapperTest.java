package com.servicenow.mid.credentials;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.servicenow.mid.credentials.config.VaultConfig;
import com.servicenow.mid.credentials.model.ResolvedCredential;
import com.servicenow.mid.credentials.util.CredentialMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CredentialMapper and VaultConfig parsing.
 * These tests run without a live vault — pure logic validation.
 */
class CredentialMapperTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    // ── USERNAME + PASSWORD ───────────────────────────────────────────────────

    @Test
    void testMapUsernamePassword_standardKeys() {
        ObjectNode data = JSON.createObjectNode();
        data.put("username", "root");
        data.put("password", "s3cr3t!");

        ResolvedCredential cred = CredentialMapper.map(data, "ssh_password", null);

        assertEquals(ResolvedCredential.CredentialType.USERNAME_PASSWORD, cred.getCredentialType());
        assertEquals("root", cred.getUserName());
        assertEquals("s3cr3t!", cred.getPassword());
    }

    @Test
    void testMapUsernamePassword_usernameHintOverridesVaultUser() {
        ObjectNode data = JSON.createObjectNode();
        data.put("username", "vault-user");
        data.put("password", "p@ssword");

        ResolvedCredential cred = CredentialMapper.map(data, "ssh_password", "hint-user");

        assertEquals("hint-user", cred.getUserName());
        assertEquals("p@ssword", cred.getPassword());
    }

    @ParameterizedTest
    @ValueSource(strings = {"password", "pass", "secret", "passwd"})
    void testMapUsernamePassword_passwordAliases(String passwordFieldName) {
        ObjectNode data = JSON.createObjectNode();
        data.put("user_name", "admin");
        data.put(passwordFieldName, "mypassword");

        ResolvedCredential cred = CredentialMapper.map(data, "basic", null);
        assertEquals("mypassword", cred.getPassword());
    }

    // ── SSH KEY ───────────────────────────────────────────────────────────────

    @Test
    void testMapSshKey_withPassphrase() {
        ObjectNode data = JSON.createObjectNode();
        data.put("user_name", "ec2-user");
        data.put("ssh_private_key", "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----");
        data.put("ssh_passphrase", "keypassphrase");

        ResolvedCredential cred = CredentialMapper.map(data, "ssh_private_key", null);

        assertEquals(ResolvedCredential.CredentialType.SSH_KEY, cred.getCredentialType());
        assertEquals("ec2-user", cred.getUserName());
        assertTrue(cred.getSshPrivateKey().contains("BEGIN PRIVATE KEY"));
        assertEquals("keypassphrase", cred.getSshPassphrase());
    }

    @Test
    void testMapSshKey_withoutPassphrase() {
        ObjectNode data = JSON.createObjectNode();
        data.put("username", "ubuntu");
        data.put("key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...");

        ResolvedCredential cred = CredentialMapper.map(data, "ssh_key", null);

        assertEquals(ResolvedCredential.CredentialType.SSH_KEY, cred.getCredentialType());
        assertNull(cred.getSshPassphrase());
    }

    // ── WINDOWS / NTLM ────────────────────────────────────────────────────────

    @Test
    void testMapWindows_withDomain() {
        ObjectNode data = JSON.createObjectNode();
        data.put("username", "svc_account");
        data.put("password", "WinP@ss!");
        data.put("windows_domain", "CORP");

        ResolvedCredential cred = CredentialMapper.map(data, "windows", null);

        assertEquals(ResolvedCredential.CredentialType.WINDOWS_NTLM, cred.getCredentialType());
        assertEquals("svc_account", cred.getUserName());
        assertEquals("WinP@ss!", cred.getPassword());
        assertEquals("CORP", cred.getWindowsDomain());
    }

    @Test
    void testMapWindows_withoutDomain() {
        ObjectNode data = JSON.createObjectNode();
        data.put("user_name", "admin");
        data.put("pass", "Admin123");

        ResolvedCredential cred = CredentialMapper.map(data, "ntlm", null);

        assertEquals(ResolvedCredential.CredentialType.WINDOWS_NTLM, cred.getCredentialType());
        assertNull(cred.getWindowsDomain());
    }

    // ── API KEY ───────────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"api_key", "token", "access_token", "bearer_token", "secret_token"})
    void testMapApiKey_aliases(String fieldName) {
        ObjectNode data = JSON.createObjectNode();
        data.put(fieldName, "eyJhbGciOiJSUzI1NiJ9...");

        ResolvedCredential cred = CredentialMapper.map(data, "api_key", null);

        assertEquals(ResolvedCredential.CredentialType.API_KEY_BEARER, cred.getCredentialType());
        assertEquals("eyJhbGciOiJSUzI1NiJ9...", cred.getApiKey());
    }

    // ── AZURE SERVICE PRINCIPAL ───────────────────────────────────────────────

    @Test
    void testMapAzureServicePrincipal() {
        ObjectNode data = JSON.createObjectNode();
        data.put("client_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        data.put("client_secret", "superSecretClientSecret");
        data.put("tenant_id", "ffffffff-0000-1111-2222-333333333333");

        ResolvedCredential cred = CredentialMapper.map(data, "azure_sp", null);

        assertEquals(ResolvedCredential.CredentialType.AZURE_SERVICE_PRINCIPAL,
                cred.getCredentialType());
        assertEquals("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", cred.getUserName());
        assertEquals("superSecretClientSecret", cred.getPassword());
        assertEquals("ffffffff-0000-1111-2222-333333333333", cred.getTenantId());
    }

    @Test
    void testMapAzureServicePrincipal_applicationIdAlias() {
        ObjectNode data = JSON.createObjectNode();
        data.put("application_id", "my-app-id");
        data.put("secret", "my-secret");

        ResolvedCredential cred = CredentialMapper.map(data, "service_principal", null);

        assertEquals("my-app-id", cred.getUserName());
        assertEquals("my-secret", cred.getPassword());
    }

    // ── VAULT CONFIG PARSING ──────────────────────────────────────────────────

    @Test
    void testVaultConfig_hashicorpAppRole() {
        Map<String, String> midProps = new HashMap<>();
        midProps.put("mid.external_credentials.vault.type", "hashicorp");
        midProps.put("mid.external_credentials.vault.url", "https://vault.example.com");
        midProps.put("mid.external_credentials.vault.auth_method", "approle");
        midProps.put("mid.external_credentials.vault.role_id", "my-role-id");
        midProps.put("mid.external_credentials.vault.secret_id", "my-secret-id");
        midProps.put("mid.external_credentials.vault.kv_version", "2");

        Map<String, String> credAttrs = new HashMap<>();
        credAttrs.put("credential_id", "secret/data/prod/linux");
        credAttrs.put("type", "ssh_password");

        VaultConfig cfg = VaultConfig.from(midProps, credAttrs);

        assertEquals(VaultConfig.VaultType.HASHICORP, cfg.getVaultType());
        assertEquals(VaultConfig.AuthMethod.APPROLE, cfg.getAuthMethod());
        assertEquals("my-role-id", cfg.getHcRoleId());
        assertEquals(2, cfg.getHcKvVersion());
        assertEquals("secret/data/prod/linux", cfg.getCredentialId());
    }

    @Test
    void testVaultConfig_cyberArk() {
        Map<String, String> midProps = new HashMap<>();
        midProps.put("mid.external_credentials.vault.type", "cyberark");
        midProps.put("mid.external_credentials.vault.url", "https://cyberark.corp.example.com");
        midProps.put("mid.external_credentials.vault.auth_method", "mtls");
        midProps.put("mid.external_credentials.vault.mtls_cert", "/etc/mid/client.pem");
        midProps.put("mid.external_credentials.vault.mtls_key", "/etc/mid/client.key");

        Map<String, String> credAttrs = new HashMap<>();
        credAttrs.put("credential_id", "MIDServer-App|Linux-Prod|root-server01");
        credAttrs.put("type", "ssh_password");

        VaultConfig cfg = VaultConfig.from(midProps, credAttrs);

        assertEquals(VaultConfig.VaultType.CYBERARK, cfg.getVaultType());
        assertEquals(VaultConfig.AuthMethod.MTLS, cfg.getAuthMethod());
        assertEquals("/etc/mid/client.pem", cfg.getMtlsCertPath());
    }

    @Test
    void testVaultConfig_missingRequiredVaultUrl_throws() {
        Map<String, String> midProps = new HashMap<>();
        midProps.put("mid.external_credentials.vault.type", "hashicorp");
        // vault.url deliberately missing

        Map<String, String> credAttrs = new HashMap<>();
        credAttrs.put("credential_id", "some/path");

        assertThrows(IllegalArgumentException.class,
                () -> VaultConfig.from(midProps, credAttrs));
    }

    @Test
    void testVaultConfig_defaultsApplied() {
        Map<String, String> midProps = new HashMap<>();
        midProps.put("mid.external_credentials.vault.type", "hashicorp");
        midProps.put("mid.external_credentials.vault.url", "https://vault.example.com");
        // No auth_method, mount_path, kv_version, timeouts → defaults should apply

        Map<String, String> credAttrs = new HashMap<>();
        credAttrs.put("credential_id", "my-secret");

        VaultConfig cfg = VaultConfig.from(midProps, credAttrs);

        assertEquals(10_000, cfg.getTimeoutMs());
        assertEquals(3,      cfg.getRetryCount());
        assertEquals("secret", cfg.getHcMountPath());
        assertEquals(2,       cfg.getHcKvVersion());
        assertEquals(VaultConfig.AuthMethod.STATIC_TOKEN, cfg.getAuthMethod());
    }

    // ── MISSING FIELD ERROR ───────────────────────────────────────────────────

    @Test
    void testMap_missingRequiredField_throwsWithContext() {
        ObjectNode data = JSON.createObjectNode();
        data.put("username", "admin");
        // password field deliberately omitted

        var ex = assertThrows(com.servicenow.mid.credentials.core.CredentialResolverException.class,
                () -> CredentialMapper.map(data, "ssh_password", null));

        assertEquals(com.servicenow.mid.credentials.core.CredentialResolverException.ErrorCode
                .MISSING_SECRET_FIELD, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("password"));
    }
}
