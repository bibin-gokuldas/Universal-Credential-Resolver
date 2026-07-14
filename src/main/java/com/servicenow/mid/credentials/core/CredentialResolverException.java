package com.servicenow.mid.credentials.core;

/**
 * Typed exception hierarchy for the Universal Credential Resolver.
 *
 * <p>ServiceNow's {@code IExternalCredential.resolve()} declares no checked
 * exceptions, so all failures surface as {@code RuntimeException}. The
 * sub-types allow callers to distinguish auth failures (retriable with
 * back-off) from configuration errors (non-retriable).</p>
 */
public class CredentialResolverException extends RuntimeException {

    private final ErrorCode errorCode;

    public enum ErrorCode {
        /** Vault server unreachable or returned HTTP 5xx */
        VAULT_UNAVAILABLE,
        /** Authentication to the vault failed (bad token/cert/role) */
        VAULT_AUTH_FAILED,
        /** Secret path / object not found (HTTP 404) */
        SECRET_NOT_FOUND,
        /** Required field missing from the resolved secret */
        MISSING_SECRET_FIELD,
        /** Configuration is incomplete or malformed */
        CONFIGURATION_ERROR,
        /** Response could not be parsed */
        PARSE_ERROR,
        /** Unknown / unclassified error */
        UNKNOWN
    }

    public CredentialResolverException(ErrorCode code, String message) {
        super("[" + code + "] " + message);
        this.errorCode = code;
    }

    public CredentialResolverException(ErrorCode code, String message, Throwable cause) {
        super("[" + code + "] " + message, cause);
        this.errorCode = code;
    }

    public ErrorCode getErrorCode() { return errorCode; }

    /** True if a transient error that may succeed on retry */
    public boolean isRetriable() {
        return errorCode == ErrorCode.VAULT_UNAVAILABLE;
    }
}
