# ServiceNow Universal External Credential Resolver
**Version:** 1.0.0  
**Compatibility:** ServiceNow Vancouver / Washington / Xanadu / Yokohama / Zurich / Australia  
**Java:** 11+

---

## Architecture

```
ServiceNow Instance
      │  credential record (type, credential_id, user_name)
      ▼
MID Server (JVM)
      │  calls IExternalCredential.resolve()
      ▼
┌─────────────────────────────────────────────────────┐
│       UniversalCredentialResolver                   │
│  ┌──────────────┐  ┌────────────────┐               │
│  │ VaultConfig  │  │  CredentialMapper│              │
│  │ (from MID    │  │  (type → SN    │               │
│  │  properties) │  │   key map)     │               │
│  └──────────────┘  └────────────────┘               │
│           │                                         │
│  ┌─────────────────────────────────────────────┐    │
│  │           VaultProviderFactory               │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐    │    │
│  │  │HashiCorp │ │CyberArk  │ │Azure KV  │    │    │
│  │  │Provider  │ │Provider  │ │Provider  │    │    │
│  │  └──────────┘ └──────────┘ └──────────┘    │    │
│  │  ┌──────────┐ ┌──────────┐                 │    │
│  │  │AWS SM    │ │Delinea   │                 │    │
│  │  │Provider  │ │Provider  │                 │    │
│  │  └──────────┘ └──────────┘                 │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
      │  VaultHttpClient (OkHttp + SigV4 + mTLS)
      ▼
 Vault Backend (HashiCorp / CyberArk / Azure KV / AWS SM / Delinea)
```

---

## Supported Vault Backends

| Backend | `vault.type` value | Auth Methods Supported |
|---|---|---|
| HashiCorp Vault | `hashicorp` | Static Token, AppRole, mTLS cert auth |
| CyberArk CCP | `cyberark` | mTLS client cert, Bearer token |
| Azure Key Vault | `azure_kv` | Managed Identity (IMDS), Service Principal |
| AWS Secrets Manager | `aws_sm` | IAM Instance Role (IMDSv2), Static credentials |
| Delinea Secret Server | `delinea` | Password grant (OAuth2), mTLS |

## Supported Credential Types

| SN Type | Vault Keys Expected | Notes |
|---|---|---|
| `ssh_password`, `snmp`, `basic` | `username`, `password` | Default mapping |
| `ssh_private_key` | `ssh_private_key`, `username`, `ssh_passphrase` | `ssh_passphrase` optional |
| `windows`, `ntlm` | `username`, `password`, `windows_domain` | `domain` optional |
| `api_key`, `bearer` | `api_key` or `token` or `access_token` | Multiple aliases |
| `azure_sp`, `service_principal` | `client_id`, `client_secret`, `tenant_id` | `tenant_id` optional override |

---

## Build

```bash
# Prerequisites: Java 11+, Maven 3.8+, agent.jar from your MID Server
./build.sh /opt/servicenow/mid/agent/lib/agent.jar

# Output: target/sn-universal-credential-resolver-1.0.0.jar
```

---

## ServiceNow Registration

1. Navigate to **Discovery → Credential Stores → External Credential Stores**
2. Click **New**
3. Fill in:
   - **Name:** `Universal Credential Resolver`
   - **Java class name:** `com.servicenow.mid.credentials.UniversalCredentialResolver`
   - **JAR file attachment:** Upload `sn-universal-credential-resolver-1.0.0.jar`
4. Save and **Distribute to all MID Servers**

---

## MID Server System Properties

Configure via **MID Server → Properties** or `config.xml`.

### Common (Required for all vault types)

| Property | Description | Example |
|---|---|---|
| `mid.external_credentials.vault.type` | Vault backend | `hashicorp` |
| `mid.external_credentials.vault.url` | Vault base URL | `https://vault.corp.example.com` |
| `mid.external_credentials.vault.auth_method` | Auth method | `approle` |
| `mid.external_credentials.vault.timeout_ms` | HTTP timeout (default: 10000) | `15000` |
| `mid.external_credentials.vault.retry_count` | Retry attempts (default: 3) | `3` |

### HashiCorp Vault

| Property | Description |
|---|---|
| `mid.external_credentials.vault.namespace` | Enterprise namespace (optional) |
| `mid.external_credentials.vault.token` | Static token (auth_method=token) |
| `mid.external_credentials.vault.role_id` | AppRole role_id |
| `mid.external_credentials.vault.secret_id` | AppRole secret_id |
| `mid.external_credentials.vault.mount_path` | KV mount (default: `secret`) |
| `mid.external_credentials.vault.kv_version` | KV version: `1` or `2` (default: `2`) |

### mTLS (all backends)

| Property | Description |
|---|---|
| `mid.external_credentials.vault.mtls_cert` | Path to PEM client certificate |
| `mid.external_credentials.vault.mtls_key` | Path to PKCS8 PEM private key |
| `mid.external_credentials.vault.ca_cert` | Path to custom CA certificate (optional) |

### AWS Secrets Manager

| Property | Description |
|---|---|
| `mid.external_credentials.aws.region` | AWS region (default: `us-east-1`) |
| `mid.external_credentials.vault.token` | `ACCESS_KEY:SECRET_KEY` for STATIC_TOKEN auth |

### Azure Key Vault

| Property | Description |
|---|---|
| `mid.external_credentials.azure.tenant_id` | Azure AD tenant ID |
| `mid.external_credentials.azure.client_id` | SP client ID (STATIC_TOKEN auth) |
| `mid.external_credentials.azure.client_secret` | SP client secret (STATIC_TOKEN auth) |

### Delinea Secret Server

| Property | Description |
|---|---|
| `mid.external_credentials.vault.role_id` | Username for OAuth2 password grant |
| `mid.external_credentials.vault.secret_id` | Password for OAuth2 password grant |

---

## Credential Record Configuration

| Field | Value |
|---|---|
| **Type** | Any SN credential type |
| **Credential ID** | Vault-specific path/name (see below) |
| **External Store** | Universal Credential Resolver |
| **Username** | Optional hint (overrides vault-returned username) |

### credential_id Formats

| Vault | Format | Example |
|---|---|---|
| HashiCorp KV v2 | Secret path (no `/data/` prefix) | `prod/linux/root` |
| HashiCorp KV v1 | Mount-relative path | `secret/prod/linux` |
| CyberArk | `AppID\|Safe\|ObjectName` | `MIDApp\|Linux-Prod\|root-server01` |
| Azure KV | Secret name (or name/version) | `prod-linux-password` |
| AWS SM | Secret name or ARN | `prod/linux/root` |
| Delinea | Numeric ID or secret path | `42` or `/Linux/prod/root` |

---

## Multi-Value Secrets (Structured Credentials)

For credential types requiring multiple fields (SSH key, Windows, Azure SP),
store the secret as a JSON object in the vault:

**HashiCorp KV v2 example:**
```json
{
  "username": "root",
  "ssh_private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "ssh_passphrase": "optional"
}
```

**AWS SM / Azure KV** (store JSON string as secret value):
```json
{
  "client_id": "aaa-bbb-ccc",
  "client_secret": "my-secret",
  "tenant_id": "xxx-yyy-zzz"
}
```

---

## Security Notes

1. **Token caching** — AppRole, Managed Identity, and SP tokens are cached in-memory at 80% of their TTL. No credential values are ever cached.
2. **mTLS key storage** — Store client keys on the MID Server host with file permissions `400` owned by the MID Server service account.
3. **Classpath isolation** — All third-party dependencies (OkHttp, Jackson) are shaded under `com.servicenow.mid.shaded.*` to prevent conflicts with existing MID Server libraries.
4. **Secrets in logs** — Credential values are NEVER logged. Only metadata (provider name, credential type, user name) appears in logs.

---

## Extending with a New Vault

1. Implement `VaultProvider` in `com.servicenow.mid.credentials.providers`
2. Add your `VaultType` enum value to `VaultConfig.VaultType`
3. Register in `VaultProviderFactory` constructor
4. Rebuild and redeploy the JAR
