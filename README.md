# ServiceNow Universal External Credential Resolver

**Version 1.0.0** | **Status:** APPROVED FOR DEPLOYMENT  
**Maven:** `com.servicenow.mid:sn-universal-credential-resolver:1.0.0`  
**Compatibility:** ServiceNow Vancouver → Australia (all current releases) | **Java:** 11+ (LTS)

> 📖 **For complete documentation, see:** `SN-Universal-Credential-Resolver-Technical-Guide.md`

---

## What This Solves

✅ Credentials **never stored in ServiceNow** — resolved live from vault at discovery time  
✅ **One JAR, all customers** — no per-customer rebuilds  
✅ **Five vault backends** with full auth method coverage  
✅ **Token caching** prevents vault thundering-herd  

**→ For full problem statement & impact analysis, see Guide Section 1**

---

## Quick Start (5 Minutes)

### 1. Build the JAR

```bash
./build.sh /opt/servicenow/mid/agent/lib/agent.jar
# Output: target/sn-universal-credential-resolver-1.0.0.jar
```

**→ For detailed build steps with prerequisites, see Guide Section 4 (Steps 1–5)**

### 2. Upload to ServiceNow

**Discovery → Credential Stores → External Credential Stores → New**

```
Name:         Universal Credential Resolver
Java class:   com.servicenow.mid.credentials.UniversalCredentialResolver
JAR file:     sn-universal-credential-resolver-1.0.0.jar
```

### 3. Configure MID Server

**MID Server → Properties** — add minimum properties:

```properties
mid.external_credentials.vault.type       = hashicorp | cyberark | azure_kv | aws_sm | delinea
mid.external_credentials.vault.url        = https://vault.corp.example.com
mid.external_credentials.vault.auth_method= token | approle | azure_mi | aws_iam | mtls
```

**→ For all properties by backend, see Guide Section 3**

### 4. Create Vault Secret & SN Credential

Store secret in vault with standard field names (resolver uses alias-based matching).

Create SN credential record pointing to vault path (`credential_id` format varies by backend).

**→ For field naming conventions & credential_id formats, see Guide Section 4 Steps 8–9**

### 5. Validate

Run Quick Discovery against a test host. Check MID Server log for:

```
[INFO] Credential resolved successfully: provider=HashiCorp Vault, type=USERNAME_PASSWORD
```

**→ For full validation walkthrough, see Guide Section 4 Step 11**

---

## Supported Backends

| Backend | `vault.type` | Auth Methods |
|---------|---|---|
| HashiCorp Vault | `hashicorp` | Static Token, AppRole, mTLS |
| CyberArk CCP | `cyberark` | mTLS, Bearer Token |
| Azure Key Vault | `azure_kv` | Managed Identity, Service Principal |
| AWS Secrets Manager | `aws_sm` | IAM Instance Role (IMDSv2), Static credentials |
| Delinea Secret Server | `delinea` | OAuth2 Password Grant, mTLS |

**→ For auth method details & secret format examples, see Guide Section 2.3 & 4 Step 8**

---

## Configuration Examples

### HashiCorp Vault + AppRole

```properties
mid.external_credentials.vault.type         = hashicorp
mid.external_credentials.vault.url          = https://vault.corp.example.com
mid.external_credentials.vault.auth_method  = approle
mid.external_credentials.vault.role_id      = my-role-id
mid.external_credentials.vault.secret_id    = my-secret-id
mid.external_credentials.vault.mount_path   = secret
mid.external_credentials.vault.kv_version   = 2
```

### CyberArk CCP + mTLS

```properties
mid.external_credentials.vault.type         = cyberark
mid.external_credentials.vault.url          = https://cyberark.corp.example.com
mid.external_credentials.vault.auth_method  = mtls
mid.external_credentials.vault.mtls_cert    = /etc/mid/client.pem
mid.external_credentials.vault.mtls_key     = /etc/mid/client.key
```

### AWS Secrets Manager + IAM Role

```properties
mid.external_credentials.vault.type         = aws_sm
mid.external_credentials.vault.url          = https://secretsmanager.ap-southeast-1.amazonaws.com
mid.external_credentials.vault.auth_method  = aws_iam
mid.external_credentials.aws.region         = ap-southeast-1
```

### Azure Key Vault + Managed Identity

```properties
mid.external_credentials.vault.type         = azure_kv
mid.external_credentials.vault.url          = https://my-vault.vault.azure.net
mid.external_credentials.vault.auth_method  = azure_mi
```

**→ For complete property reference covering ALL backends, see Guide Section 3**

---

## Error Reference

| Code | Cause | Action |
|---|---|---|
| `CONFIGURATION_ERROR` | Missing MID property | Check **MID Server → Properties**; restart |
| `VAULT_AUTH_FAILED` | Wrong token/AppRole/cert | Verify credentials; check vault audit logs |
| `SECRET_NOT_FOUND` | Path doesn't exist | Confirm path exists in vault |
| `MISSING_SECRET_FIELD` | Required field missing | Add missing field to vault secret |
| `VAULT_UNAVAILABLE` | Network/TLS issue | Check connectivity & CA cert trust |
| `PARSE_ERROR` | Unexpected vault response | Check vault version; enable DEBUG logging |

**→ For full error code table with detailed resolutions, see Guide Section 5**

---

## Enable Debug Logging

Add to MID Server `agent/config.xml`:

```xml
<parameter name="mid.log.level" value="debug"/>
```

🔒 **Security:** Debug logs do NOT emit credential values — only metadata.

**→ For full troubleshooting guide & extension instructions, see Guide Section 5**

---

## Security Highlights

**Built-in (by design):**
- Credentials never stored in SN
- Credentials never logged
- Token caching at 80% TTL (credential values never cached)
- Classpath isolation (all deps shaded)
- mTLS support
- Exponential backoff on transient failures

**Customer-configured:**
- Least-privilege vault roles
- MID host key hardening (`chmod 400`)
- Network segmentation
- Vault audit logging
- Secret rotation (quarterly)

**→ For complete security controls matrix, see Guide Section 6**

---

## Architecture

```
SN Instance → MID Server JVM → Vault Backend
                ├─ UniversalCredentialResolver
                ├─ VaultConfig (from MID props)
                ├─ VaultProviderFactory
                ├─ VaultHttpClient (retry/mTLS)
                └─ CredentialMapper (type → SN keys)
```

**→ For full architecture diagram & component details, see Guide Section 2.2**

---

## FAQ

**Q: Can I use different vaults for different customers?**  
A: Yes. Each MID Server configured with ONE vault backend. For multiple vaults, deploy separate MID Servers.

**Q: Are credentials cached?**  
A: NO — credential values never cached. Only auth tokens cached at 80% TTL.

**Q: What if vault is down?**  
A: Discovery fails with `VAULT_UNAVAILABLE`. Resolver retries transient failures. Reschedule discovery when vault online.

**Q: Can I override the username from vault?**  
A: Yes. Populate **Username** field in SN credential record.

**→ For complete FAQ, see Guide Section 4 (bottom) & comprehensive FAQs**

---

## Project Structure

```
sn-universal-credential-resolver/
├── pom.xml                              (Maven build)
├── build.sh                             (One-command build)
├── README.md                            (This file)
├── src/main/java/.../credentials/
│   ├── UniversalCredentialResolver.java (SPI entry point)
│   ├── config/VaultConfig.java
│   ├── core/ (VaultProvider, VaultProviderFactory, exceptions)
│   ├── model/ (ResolvedCredential DTO)
│   ├── providers/ (5 vault backends)
│   └── util/ (VaultHttpClient, CredentialMapper)
└── src/test/java/.../CredentialMapperTest.java (20+ unit tests)
```

---

## Next Steps

1. **Read the Full Guide** → `SN-Universal-Credential-Resolver-Technical-Guide.md`
   - Section 1: Problem Statement & Business Impact
   - Section 2: Solution Architecture
   - Section 3: Configuration Reference (all backends, all properties)
   - Section 4: Developer Guide (11-step deployment walkthrough)
   - Section 5: Troubleshooting & Extension
   - Section 6: Security Controls

2. **Follow Steps 1–11** in Guide Section 4 for complete deployment

3. **Extend with New Vault** → Guide Section 5.2 (implement `VaultProvider` interface)

---

## Support

- **Configuration issues** → Guide Section 3 (property reference)
- **Build/Deployment** → Guide Section 4 (steps 1–11)
- **Error codes** → Guide Section 5 (error table + solutions)
- **Security review** → Guide Section 6 (controls matrix + checklists)
- **Adding a vault backend** → Guide Section 5.2

---

**Classification:** Internal | **Version:** 1.0.0 | **Author:** Platform Architecture | CEG APAC  
**Status:** APPROVED FOR DEPLOYMENT