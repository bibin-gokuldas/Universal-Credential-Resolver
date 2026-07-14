# ServiceNow Universal External Credential Resolver
**Technical Design, Configuration & Developer Guide**

| Attribute | Value |
|-----------|-------|
| **Version** | 1.0.0 |
| **Release Date** | July 2026 |
| **Artifact ID** | sn-universal-credential-resolver |
| **Maven Coordinates** | `com.servicenow.mid:sn-universal-credential-resolver:1.0.0` |
| **SN Compatibility** | Vancouver → Australia (all current releases) |
| **Java Baseline** | Java 11+ (LTS) |
| **Author** | Platform Architecture \| CEG APAC |
| **Status** | APPROVED FOR DEPLOYMENT |
| **Classification** | Internal |

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Solution Overview](#2-solution-overview)
3. [Configuration Reference](#3-configuration-reference)
4. [Developer Step-by-Step Guide](#4-developer-step-by-step-guide)
5. [Troubleshooting Reference](#5-troubleshooting-reference)
6. [Security Considerations](#6-security-considerations)

---

# 1. Problem Statement

ServiceNow Discovery and integrations authenticate to managed devices and external systems using credential records stored inside the ServiceNow instance. In organisations with mature security postures, these credentials are **NOT** stored in ServiceNow — they are held in enterprise-grade vault systems such as HashiCorp Vault, CyberArk, Azure Key Vault, AWS Secrets Manager, or Delinea Secret Server.

## 1.1 The Core Problem

Without a unified external credential resolver, organisations face one or more of the following compromises:

- **Credentials stored in ServiceNow plaintext** (or encrypted with the platform key) — violating PAM policy and creating a single point of compromise.
- **Custom one-off JAR files built per customer, per vault** — inconsistent, hard to maintain, with no shared test coverage.
- **Discovery disabled for privileged systems** — leaving significant asset inventory and CMDB gaps.
- **Vault integrations maintained by individual delivery teams** — no knowledge transfer, no org standard.
- **Security audit findings raised on every customer engagement** for the same root-cause issue.

## 1.2 Impact Without a Solution

| Impact Area | Consequence | Severity | Affected Teams |
|---|---|---|---|
| **Security & Compliance** | Credentials stored in SN violate SOC 2, ISO 27001, MAS TRM, and most enterprise PAM policies | 🔴 CRITICAL | CISO, Audit, Risk |
| **CMDB Accuracy** | Discovery cannot authenticate to servers → missing CIs, broken service maps, unreliable CMDB | 🟠 HIGH | Platform Ops, ITOM |
| **Delivery Consistency** | Each customer project rebuilds the same solution independently, wasting delivery days | 🟠 HIGH | PA, TA, Delivery |
| **Upgrade Risk** | Customer-specific JARs may break on SN release upgrades with no structured regression path | 🟡 MEDIUM | Delivery, Upgrade |
| **Operational Cost** | Passwords expire → Discovery failures → P2/P3 incidents raised against platform team | 🟡 MEDIUM | Platform Ops, CEG |

## 1.3 Why Existing Approaches Fall Short

- **ServiceNow's OOB CyberArk integration** requires the CyberArk AIM agent installed on the MID Server host — not allowed in most hardened environments.
- **HashiCorp Vault has no OOB SN connector** for credential resolution (only ITOMv integrations exist).
- **AWS and Azure vault integrations are entirely absent** from the SN platform natively.
- **Per-customer JARs lack multi-vault support** — if a customer migrates from CyberArk to HashiCorp, a full rebuild is required.

---

# 2. Solution Overview

The **Universal External Credential Resolver** is a production-grade, organisation-wide ServiceNow MID Server plugin (JAR file) that implements the ServiceNow `IExternalCredential` SPI. It routes any credential resolution request to the appropriate vault backend based on a **single MID Server system property** — with zero code changes required when switching vault providers.

## 2.1 What It Solves

✅ **Credentials NEVER touch ServiceNow storage** — they are resolved live from the vault at discovery time.

✅ **One JAR file deployed once at org level** covers ALL customers and ALL vault backends.

✅ **New vault backends can be added** by implementing a single Java interface — no SPI changes.

✅ **Token caching at 80% TTL** eliminates thundering-herd vault auth calls during large discovery schedules.

✅ **Full credential type coverage**: SSH Key, Username/Password, Windows/NTLM, API Key/Bearer, Azure Service Principal.

## 2.2 Architecture

```
┌─────────────────────────────────────────────────────┐
│  ServiceNow Instance                                │
│  └─ Credential record (type, credential_id, user)  │
└─────────────────────────────────────────────────────┘
              │
              ▼ calls IExternalCredential.resolve()
┌─────────────────────────────────────────────────────┐
│  MID Server JVM                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │  UniversalCredentialResolver                  │  │
│  │  ├─ VaultConfig (from MID properties)         │  │
│  │  ├─ VaultProviderFactory                      │  │
│  │  ├─ VaultHttpClient (retry/mTLS/backoff)     │  │
│  │  └─ CredentialMapper (type → SN key map)     │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
              │
              ▼ HTTP/HTTPS (SigV4 / OAuth2 / mTLS)
┌─────────────────────────────────────────────────────┐
│  Vault Backends                                     │
│  ✓ HashiCorp Vault                                 │
│  ✓ CyberArk CCP                                    │
│  ✓ Azure Key Vault                                 │
│  ✓ AWS Secrets Manager                             │
│  ✓ Delinea Secret Server                           │
└─────────────────────────────────────────────────────┘
```

## 2.3 Supported Vault Backends & Auth Methods

| Vault Backend | `vault.type` Value | Supported Auth Methods | Secret Format |
|---|---|---|---|
| **HashiCorp Vault** | `hashicorp` | Static Token, AppRole, mTLS Cert Auth | KV v1 & v2 (JSON object) |
| **CyberArk CCP** | `cyberark` | mTLS Client Cert, Bearer Token | Flat object (AIM API) |
| **Azure Key Vault** | `azure_kv` | Managed Identity (IMDS), Service Principal | String value or JSON string |
| **AWS Secrets Manager** | `aws_sm` | IAM Instance Role (IMDSv2), Static keys + SigV4 | SecretString — plain or JSON |
| **Delinea Secret Server** | `delinea` | OAuth2 Password Grant, mTLS | items[] array (field/value) |

---

# 3. Configuration Reference

All configuration is driven by **MID Server system properties**. No code changes are required to switch vault backends, change auth methods, or onboard a new customer.

## 3.1 Universal MID Server Properties (All Backends)

| Property Name | Required | Default | Description |
|---|---|---|---|
| `mid.external_credentials.vault.type` | **YES** | — | Vault backend: `hashicorp` \| `cyberark` \| `azure_kv` \| `aws_sm` \| `delinea` |
| `mid.external_credentials.vault.url` | **YES** | — | Base URL of the vault endpoint |
| `mid.external_credentials.vault.auth_method` | NO | `token` | Auth method: `token` \| `approle` \| `azure_mi` \| `aws_iam` \| `mtls` |
| `mid.external_credentials.vault.timeout_ms` | NO | `10000` | HTTP connect + read timeout in milliseconds |
| `mid.external_credentials.vault.retry_count` | NO | `3` | Number of retries on transient 5xx / IO errors |

## 3.2 HashiCorp Vault Properties

| Property | Required | Default | Description |
|---|---|---|---|
| `mid.external_credentials.vault.token` | Conditional | — | Static Vault token (`auth_method=token` only) |
| `mid.external_credentials.vault.role_id` | Conditional | — | AppRole role_id (`auth_method=approle`) |
| `mid.external_credentials.vault.secret_id` | Conditional | — | AppRole secret_id (`auth_method=approle`) |
| `mid.external_credentials.vault.mount_path` | NO | `secret` | KV secrets engine mount path |
| `mid.external_credentials.vault.kv_version` | NO | `2` | KV version: `1` or `2` |
| `mid.external_credentials.vault.namespace` | NO | — | Enterprise namespace (e.g. `admin/team1`) |

## 3.3 mTLS Properties (Applicable to All Backends)

| Property | Required | Default | Description |
|---|---|---|---|
| `mid.external_credentials.vault.mtls_cert` | Conditional | — | Absolute path to PEM client certificate on MID Server host |
| `mid.external_credentials.vault.mtls_key` | Conditional | — | Absolute path to PKCS8 PEM private key on MID Server host |
| `mid.external_credentials.vault.ca_cert` | NO | JVM trust store | Custom CA certificate path (for self-signed vault TLS) |

## 3.4 AWS Secrets Manager Properties

| Property | Required | Default | Description |
|---|---|---|---|
| `mid.external_credentials.aws.region` | NO | `us-east-1` | AWS region |
| `mid.external_credentials.vault.token` | Conditional | — | For STATIC_TOKEN auth: `ACCESS_KEY:SECRET_KEY` |

## 3.5 Azure Key Vault Properties

| Property | Required | Default | Description |
|---|---|---|---|
| `mid.external_credentials.azure.tenant_id` | Conditional | — | Azure AD tenant ID (for Service Principal auth) |
| `mid.external_credentials.azure.client_id` | Conditional | — | Service Principal client ID |
| `mid.external_credentials.azure.client_secret` | Conditional | — | Service Principal client secret |

## 3.6 Delinea Secret Server Properties

| Property | Required | Default | Description |
|---|---|---|---|
| `mid.external_credentials.vault.role_id` | Conditional | — | Username for OAuth2 password grant |
| `mid.external_credentials.vault.secret_id` | Conditional | — | Password for OAuth2 password grant |

## 3.7 Credential Record Configuration

In the ServiceNow Credential record, the `credential_id` field contains the vault-specific secret path or identifier. Format differs by backend:

| Vault Backend | credential_id Format | Example |
|---|---|---|
| **HashiCorp (KV v2)** | Secret path (no `/data/` prefix) | `prod/linux/root` or `databases/oracle/prod` |
| **HashiCorp (KV v1)** | Mount-relative path | `secret/prod/linux/root` |
| **CyberArk CCP** | `AppID\|Safe\|ObjectName` (pipe-separated) | `MIDServer-App\|Linux-Prod\|root-server01` |
| **Azure Key Vault** | Secret name (or name/version) | `prod-linux-root-password` |
| **AWS Secrets Manager** | Secret name or full ARN | `prod/linux/root` or `arn:aws:sm:ap-southeast-1:…` |
| **Delinea Secret Server** | Numeric ID or folder path | `42` or `/Linux/Prod/root-server` |

---

# 4. Developer Step-by-Step Guide

This section covers every action a developer must take — from environment setup to post-deployment validation. Follow the steps in sequence.

**Estimated total time:** 2–4 hours for a first deployment; 30 minutes for subsequent customer onboardings.

## 4.1 Prerequisites

> ⚠️ **Prerequisites must be confirmed BEFORE starting.** Ensure all of the following are available before proceeding.

- Java Development Kit (JDK) 11 or later installed on the build machine
- Apache Maven 3.8+ installed and in PATH
- Access to the MID Server installation directory (to obtain `agent.jar`)
- ServiceNow Admin or `itil_admin` role on the target instance
- Network access from MID Server host to the vault backend URL
- Vault access to create an AppRole / service account for MID Server (least-privilege)
- Git access to the JAR source repository (or the source ZIP provided by the PA)

---

## Step 1: Clone / Extract the Source Code

**Objective:** Obtain the project source and verify structure.

Obtain the project source. Clone from the org Git repository or extract the provided `sn-universal-credential-resolver-src.zip` to your local machine. Confirm the following top-level structure is present: `src/`, `pom.xml`, `build.sh`, `README.md`.

```bash
unzip sn-universal-credential-resolver-src.zip
cd sn-universal-credential-resolver
ls -la
# Expected: build.sh, pom.xml, README.md, src/
```

---

## Step 2: Locate and Stage agent.jar

**Objective:** Obtain the ServiceNow MID Server SPI JAR.

Copy `agent.jar` from the MID Server installation. Path: `<MID_HOME>/agent/lib/agent.jar`. This file is the ServiceNow MID Server SPI and must match the release of your target instance. It is a provided dependency — it must **NOT** be included in the final JAR.

```bash
# Example — copy from a Linux MID Server host
scp midserver-host:/opt/servicenow/mid/agent/lib/agent.jar ./

# Or copy from the local MID Server if co-located
cp /opt/servicenow/mid/agent/lib/agent.jar ./
```

---

## Step 3: Install agent.jar into Local Maven Repository

**Objective:** Register `agent.jar` as a Maven dependency.

Run the following Maven command to register `agent.jar` as a local dependency. **This only needs to be done once per build machine.**

```bash
mvn install:install-file \
  -Dfile=./agent.jar \
  -DgroupId=com.service-now.mid \
  -DartifactId=agent \
  -Dversion=latest \
  -Dpackaging=jar
```

Expected output:
```
[INFO] Installing .../agent.jar to ~/.m2/repository/com/service-now/mid/agent/latest/agent.jar
[INFO] BUILD SUCCESS
```

---

## Step 4: Build the Fat JAR

**Objective:** Compile source and package with all dependencies.

Run the Maven build. The shade plugin packages all third-party dependencies (OkHttp, Jackson) into a single shaded JAR with relocated classpath to prevent MID Server conflicts.

```bash
mvn clean package
```

Expected output:
```
[INFO] Building jar: .../target/sn-universal-credential-resolver-1.0.0.jar
[INFO] BUILD SUCCESS
```

**Alternative:** Use the convenience wrapper script:
```bash
./build.sh ./agent.jar
# Runs Steps 3 and 4 in sequence
```

---

## Step 5: Run Unit Tests

**Objective:** Verify the build passes all unit tests before uploading.

Tests cover CredentialMapper field resolution for all credential types, VaultConfig property parsing, error code handling, and alias coverage.

```bash
mvn test
```

Expected output:
```
[INFO] Running CredentialMapperTest
[INFO] Tests run: 20, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

---

## Step 6: Upload JAR to ServiceNow

**Objective:** Register the external credential store in ServiceNow.

1. Navigate to: **Discovery → Credential Stores → External Credential Stores**
2. Click **New**
3. Fill in the following:

| Field | Value |
|-------|-------|
| **Name** | Universal Credential Resolver |
| **Java class name** | `com.servicenow.mid.credentials.UniversalCredentialResolver` |
| **JAR file attachment** | `sn-universal-credential-resolver-1.0.0.jar` (attach) |

4. Click **Save**

The JAR is now registered and will automatically distribute to all active MID Servers.

---

## Step 7: Configure MID Server System Properties

**Objective:** Define the vault backend and authentication method.

Navigate to: **MID Server → Properties** (or **Manage Properties** on the MID Server record). Add the vault configuration properties for your environment. At minimum, `vault.type`, `vault.url`, and `vault.auth_method` are required.

### Example 1: HashiCorp Vault with AppRole

```properties
mid.external_credentials.vault.type         = hashicorp
mid.external_credentials.vault.url          = https://vault.corp.example.com
mid.external_credentials.vault.auth_method  = approle
mid.external_credentials.vault.role_id      = <your-role-id>
mid.external_credentials.vault.secret_id    = <your-secret-id>
mid.external_credentials.vault.mount_path   = secret
mid.external_credentials.vault.kv_version   = 2
```

### Example 2: CyberArk CCP with mTLS

```properties
mid.external_credentials.vault.type         = cyberark
mid.external_credentials.vault.url          = https://cyberark.corp.example.com
mid.external_credentials.vault.auth_method  = mtls
mid.external_credentials.vault.mtls_cert    = /etc/mid/client.pem
mid.external_credentials.vault.mtls_key     = /etc/mid/client.key
```

### Example 3: AWS Secrets Manager with IAM Role

```properties
mid.external_credentials.vault.type         = aws_sm
mid.external_credentials.vault.url          = https://secretsmanager.ap-southeast-1.amazonaws.com
mid.external_credentials.vault.auth_method  = aws_iam
mid.external_credentials.aws.region         = ap-southeast-1
```

### Example 4: Azure Key Vault with Managed Identity

```properties
mid.external_credentials.vault.type         = azure_kv
mid.external_credentials.vault.url          = https://my-vault.vault.azure.net
mid.external_credentials.vault.auth_method  = azure_mi
```

---

## Step 8: Create Vault Secret with the Correct Structure

**Objective:** Store credentials in the vault using expected field naming conventions.

The resolver uses alias-based field matching, so minor naming variations are tolerated. The table below shows the expected structure for each credential type.

### Secret Structure by Credential Type

| SN Credential Type | Required Vault Fields | Optional Fields | Example JSON in Vault |
|---|---|---|---|
| `ssh_password` / `basic` / `snmp` | `username`, `password` | — | `{"username":"root","password":"s3cr3t"}` |
| `ssh_private_key` | `username`, `ssh_private_key` | `ssh_passphrase` | `{"username":"ec2-user","ssh_private_key":"-----BEGIN…","ssh_passphrase":"key_pass"}` |
| `windows` / `ntlm` | `username`, `password` | `windows_domain` | `{"username":"svc_account","password":"Win@123","windows_domain":"CORP"}` |
| `api_key` / `bearer` | `api_key` (or `token`) | `username` | `{"api_key":"eyJhbGci…"}` |
| `azure_sp` / `service_principal` | `client_id`, `client_secret` | `tenant_id` | `{"client_id":"aaa","client_secret":"bbb","tenant_id":"ccc"}` |

### Field Name Aliases (Convention-Based Matching)

The resolver tries multiple field names in order. The first match wins:

- **username:** `username`, `user_name`, `user`, `login`
- **password:** `password`, `pass`, `secret`, `passwd`
- **ssh_private_key:** `ssh_private_key`, `private_key`, `key`, `ssh_key`
- **ssh_passphrase:** `ssh_passphrase`, `passphrase`, `key_passphrase`
- **windows_domain:** `windows_domain`, `domain`, `ntlm_domain`
- **api_key:** `api_key`, `token`, `access_token`, `bearer_token`, `secret_token`
- **client_id:** `client_id`, `application_id`, `app_id`
- **client_secret:** `client_secret`, `secret`, `password`
- **tenant_id:** `tenant_id`, `directory_id`, `azure_tenant`

### Example: Store Secret in HashiCorp Vault (KV v2)

```bash
vault kv put secret/prod/linux/root \
  username=root \
  password='MySecureP@ssw0rd!' \
  ssh_private_key='-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt...' \
  ssh_passphrase='optional_key_passphrase'
```

### Example: Store Secret in CyberArk

Use the CyberArk Administration interface to store the secret object. Ensure the following fields are populated (UI field names may vary):
- Account Name / Username
- Password (or SSH Private Key)
- Optional: Domain (for Windows), SSH Passphrase, etc.

### Example: Store Secret in AWS Secrets Manager

```bash
aws secretsmanager create-secret \
  --name prod/linux/root \
  --secret-string '{
    "username": "root",
    "password": "MySecureP@ssw0rd!",
    "ssh_private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }' \
  --region ap-southeast-1
```

---

## Step 9: Create ServiceNow Credential Records

**Objective:** Register credentials in ServiceNow pointing to the vault secrets.

Navigate to: **Discovery → Credentials → New** (or the credential type sub-list). 

Fill in:

| Field | Value |
|-------|-------|
| **Type** | Appropriate SN credential type (e.g. `ssh_password`, `windows`, `api_key`) |
| **Name** | Descriptive name (e.g. "Prod Linux Root") |
| **Credential ID** | Vault path/identifier (see Step 8 / credential_id Format table) |
| **External Credential Store** | Universal Credential Resolver |
| **Username** | Optional hint to override vault username |

**Save the record.**

> ⚠️ **CyberArk credential_id format:** Must be pipe-separated: `AppID|Safe|ObjectName`  
> Example: `MIDServer-App|Linux-Prod|root-server01`

---

## Step 10: Distribute JAR to All MID Servers

**Objective:** Trigger distribution of the JAR to active MID Servers.

ServiceNow automatically distributes the External Credential Store JAR to all active MID Servers that handle Discovery. Verify distribution by checking the MID Server log: look for "Registered vault provider" entries from `VaultProviderFactory`.

**Expected log lines on MID Server startup:**

```
[INFO] Registered vault provider: HASHICORP → HashiCorp Vault
[INFO] Registered vault provider: CYBERARK → CyberArk CCP
[INFO] Registered vault provider: AZURE_KEY_VAULT → Azure Key Vault
[INFO] Registered vault provider: AWS_SECRETS_MANAGER → AWS Secrets Manager
[INFO] Registered vault provider: DELINEA → Delinea Secret Server
```

If a MID Server does not pick up the JAR:
1. Trigger a restart via **MID Server → [your server] → Restart**
2. Monitor the log during restart
3. Check for any ERROR lines in the log related to JAR loading

---

## Step 11: Validate with a Test Discovery

**Objective:** Run a targeted discovery using the externally-resolved credential.

Run a **Quick Discovery** or a targeted **CI Discovery** against one known host that uses an externally-resolved credential. Monitor the MID Server log in real time.

### Expected Success Log Output

```
[INFO] UniversalCredentialResolver.resolve() called: id=prod/linux/root, type=ssh_password
[DEBUG] Routing to provider: HashiCorp Vault | credential: prod/linux/root
[DEBUG] Fetching secret: https://vault.corp.example.com/v1/secret/data/prod/linux/root
[INFO] Credential resolved successfully: provider=HashiCorp Vault, type=USERNAME_PASSWORD
```

### Expected Failure Log Output (Example)

```
[ERROR] Credential resolution failed [VAULT_AUTH_FAILED]: HTTP 401 from vault: role_id / secret_id mismatch
```

### Troubleshooting Failed Resolution

If resolution fails, check MID Server log for `[ERROR]` lines containing an `ErrorCode`. See **Section 5** for the complete error code reference and resolution steps.

---

# 5. Troubleshooting Reference

## Error Codes & Solutions

| Error Code | Cause | Resolution |
|---|---|---|
| `CONFIGURATION_ERROR` | Required MID property missing (e.g. `vault.type`, `vault.url`) | Verify all required properties are set under **MID Server → Properties**. Restart MID Server after changes. |
| `VAULT_AUTH_FAILED` | Wrong token, expired AppRole `secret_id`, or certificate mismatch | Re-check `role_id` / `secret_id`. Confirm cert CN matches Vault cert auth role. Check vault audit logs for the auth failure. |
| `SECRET_NOT_FOUND` | `credential_id` path does not exist in vault, or wrong mount | Verify path by running a manual vault read. For KV v2, confirm `/data/` is NOT in the path (the resolver adds it automatically). |
| `MISSING_SECRET_FIELD` | Secret exists but required key (e.g. `password`, `ssh_private_key`) is absent | Inspect the vault secret object. Add the missing field with the correct name. See Section 4, Step 8 for field conventions. |
| `VAULT_UNAVAILABLE` | Network unreachable, TLS handshake failure, or vault sealed | Verify network connectivity from MID Server host. Check vault status (`vault status`). Confirm CA cert is trusted if custom PKI. |
| `PARSE_ERROR` | Vault returned unexpected response format | Check vault version compatibility. Enable DEBUG logging to capture full response body for analysis. |

## Enabling Debug Logging on MID Server

Add the following to the MID Server `agent/config.xml` to enable resolver debug logs:

```xml
<parameter name="mid.log.level" value="debug"/>
```

Or temporarily set via ServiceNow: **MID Server → [your server] → Log Levels → Set to DEBUG**

> 🔒 **Security Note:** Debug logs do NOT emit credential values. Only metadata (provider, credential type, secret path) appears in logs.

## Extending with a New Vault Backend

The resolver is designed for extension. To add a new vault backend:

1. **Implement the `VaultProvider` interface** in the `com.servicenow.mid.credentials.providers` package
2. **Add a new value** to `VaultConfig.VaultType` enum
3. **Register the new provider** in `VaultProviderFactory` constructor
4. **Add unit tests** to `CredentialMapperTest` covering the new backend's response format
5. **Rebuild and redeploy the JAR** — no SN configuration changes required

---

# 6. Security Considerations

## Built-In Controls (Implemented in the JAR)

| Control | Implementation | Status |
|---|---|---|
| **Credentials never stored in SN** | Resolved live from vault at discovery time; never written to SN DB | ✅ By Design |
| **Credentials never logged** | Only metadata logged; all credential values suppressed in all log paths | ✅ By Design |
| **Token caching at 80% TTL** | Auth tokens cached in-memory; expires before vault TTL to prevent stale token use | ✅ Implemented |
| **Classpath isolation** | All third-party deps shaded under `com.servicenow.mid.shaded.*` | ✅ Implemented |
| **mTLS support** | Full mutual TLS with client cert + custom CA for zero-trust vault communication | ✅ Implemented |
| **Exponential backoff** | Transient failures retried with 1s/2s/4s/8s back-off; auth failures not retried | ✅ Implemented |

## Customer-Configured Controls (Recommended Configuration)

| Control | Description | Action Required |
|---|---|---|
| **Least-privilege vault roles** | Vault AppRole / policy should have read-only access to specific secret paths only | ⚠️ Customer config |
| **MID Server host hardening** | mTLS keys stored with `chmod 400`, owned by MID service account | ⚠️ Customer config |
| **Network segmentation** | MID Server host should have network access to vault only (restrict Internet egress) | ⚠️ Customer config |
| **Vault audit logging** | Enable audit logging on vault backend to track all credential resolution calls | ⚠️ Customer config |
| **Secret rotation** | Rotate AppRole `secret_id` periodically (e.g. quarterly) | ⚠️ Customer config |

---

## Quick Reference: Configuration Checklists

### Pre-Deployment Checklist

- [ ] Build machine has JDK 11+ and Maven 3.8+
- [ ] `agent.jar` obtained from MID Server installation
- [ ] Source code cloned/extracted and verified
- [ ] Unit tests pass (`mvn test`)
- [ ] FAT JAR built successfully (`target/sn-universal-credential-resolver-1.0.0.jar` exists)
- [ ] ServiceNow Admin access confirmed
- [ ] Vault backend URL confirmed accessible from MID Server host
- [ ] Vault service account / AppRole / credentials prepared

### Deployment Checklist

- [ ] JAR uploaded to ServiceNow (**Discovery → Credential Stores → External Credential Stores**)
- [ ] MID Server properties configured with vault type, URL, auth method
- [ ] Secrets created in vault backend with correct field naming
- [ ] SN credential records created pointing to vault secrets
- [ ] JAR distribution verified on MID Server (check logs for provider registration)
- [ ] Test discovery executed against known host
- [ ] Test discovery succeeded with credential resolved (check logs for success message)
- [ ] Discovery scheduled for full environment

### Maintenance Checklist (Quarterly)

- [ ] Review MID Server logs for credential resolution errors
- [ ] Rotate vault AppRole `secret_id` (if using AppRole auth)
- [ ] Verify token caching is working (check logs for "Reusing cached token" messages)
- [ ] Check vault audit logs for unexpected resolution attempts
- [ ] Test failover to backup vault endpoint (if applicable)

---

## FAQs

### Q: Can I use different vaults for different customers/business units?

**A:** Yes. Create separate SN credential records with different `credential_id` values pointing to secrets in each vault. However, each MID Server can only be configured with ONE vault backend at a time via `vault.type`. To support multiple vaults simultaneously, you would need separate MID Servers with different property configurations.

### Q: How often are credentials resolved from the vault?

**A:** Every time a Discovery probe runs and requires the credential. There is NO caching of credential VALUES — only auth tokens are cached (AppRole tokens, Managed Identity tokens, etc.) to avoid thundering-herd on vault. A new credential resolution is triggered on each discovery execution.

### Q: What happens if the vault is unavailable during discovery?

**A:** The discovery probe will fail with a `VAULT_UNAVAILABLE` error. The resolver implements exponential backoff (1s/2s/4s/8s) for transient failures, but the discovery execution itself is not retried. Reschedule the discovery once the vault is online.

### Q: Can I override the username returned by the vault?

**A:** Yes. In the SN credential record, populate the **Username** field with the desired value. The resolver will use this as the final username, overriding any value found in the vault secret.

### Q: Does the JAR work with ServiceNow instances in different regions?

**A:** Yes. The JAR is deployed to the MID Server(s), not to the SN instance. It works with any SN instance the MID Server is connected to. However, the MID Server must have network access to the vault backend.

### Q: What if the vault secret field names don't match the resolver's expectations?

**A:** The resolver uses alias-based matching — multiple field names are tried in order until a match is found. Most common variations (e.g. `username` vs `user_name` vs `user`) are covered. If you use non-standard field names, add them to the vault secret using both the standard AND your custom name — the resolver will match the standard one.

### Q: How do I add a new vault backend (e.g. HashiCorp Vault on-premises + CyberArk)?

**A:** The resolver already supports both. Create two separate MID Server configurations:
1. MID Server A: `vault.type=hashicorp`, properties for HashiCorp
2. MID Server B: `vault.type=cyberark`, properties for CyberArk

Then in your SN credentials, assign each credential to the appropriate MID Server. Discovery will resolve credentials from the correct vault automatically.

---

**End of Document**
