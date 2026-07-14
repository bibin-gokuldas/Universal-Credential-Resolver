#!/bin/bash
# =============================================================================
# build.sh — ServiceNow Universal Credential Resolver
# =============================================================================
# Prerequisites:
#   - Java 11+
#   - Maven 3.8+
#   - agent.jar from your MID Server installation (see Step 1 below)
#
# Usage:
#   chmod +x build.sh
#   ./build.sh [path-to-agent.jar]
# =============================================================================

set -euo pipefail

AGENT_JAR="${1:-/opt/servicenow/mid/agent/lib/agent.jar}"
VERSION="1.0.0"
ARTIFACT="sn-universal-credential-resolver-${VERSION}.jar"

echo "================================================================"
echo " ServiceNow Universal Credential Resolver — Build Script"
echo "================================================================"

# ── Step 1: Install agent.jar into local Maven repo ──────────────────
if [ ! -f "$AGENT_JAR" ]; then
  echo ""
  echo "ERROR: agent.jar not found at: $AGENT_JAR"
  echo ""
  echo "  Provide the path as an argument:"
  echo "    ./build.sh /path/to/your/mid-server/agent.jar"
  echo ""
  echo "  The file is at: <MID_HOME>/agent/lib/agent.jar"
  echo ""
  exit 1
fi

echo ""
echo "[1/3] Installing agent.jar into local Maven repo..."
mvn install:install-file \
  -Dfile="$AGENT_JAR" \
  -DgroupId=com.service-now.mid \
  -DartifactId=agent \
  -Dversion=latest \
  -Dpackaging=jar \
  -q

echo "      ✓ agent.jar installed"

# ── Step 2: Build fat JAR ─────────────────────────────────────────────
echo ""
echo "[2/3] Compiling and packaging..."
mvn clean package -q

echo "      ✓ Built: target/${ARTIFACT}"

# ── Step 3: Verify ────────────────────────────────────────────────────
echo ""
echo "[3/3] Verifying JAR manifest..."
jar tf "target/${ARTIFACT}" | grep "UniversalCredentialResolver.class" && \
  echo "      ✓ Main class present" || \
  echo "      ✗ WARNING: Main class not found in JAR"

echo ""
echo "================================================================"
echo " BUILD COMPLETE"
echo "================================================================"
echo ""
echo " Output JAR: target/${ARTIFACT}"
echo " Upload this file to ServiceNow:"
echo ""
echo "   Discovery → Credential Stores → External Credential Stores"
echo "   → New → Upload JAR"
echo "   Java class: com.servicenow.mid.credentials.UniversalCredentialResolver"
echo ""
echo " Then configure MID Server system properties:"
echo "   mid.external_credentials.vault.type         = hashicorp"
echo "   mid.external_credentials.vault.url          = https://your-vault-url"
echo "   mid.external_credentials.vault.auth_method  = approle"
echo "   mid.external_credentials.vault.role_id      = <AppRole role_id>"
echo "   mid.external_credentials.vault.secret_id    = <AppRole secret_id>"
echo ""
echo " Supported vault types: hashicorp | cyberark | azure_kv | aws_sm | delinea"
echo "================================================================"
