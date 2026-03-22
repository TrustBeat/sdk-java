package eu.trustbeat.sdk;

/** Base exception for all TrustBeat SDK errors. */
public class TrustBeatException extends RuntimeException {

    private final int status;
    private final String code;

    public TrustBeatException(String message, int status, String code) {
        super(message);
        this.status = status;
        this.code   = code;
    }

    public TrustBeatException(String message, int status) {
        this(message, status, null);
    }

    public TrustBeatException(String message) {
        this(message, 0, null);
    }

    /** HTTP status code, or 0 if not applicable. */
    public int getStatus() { return status; }

    /** Machine-readable error code returned by the API, or null. */
    public String getCode()   { return code; }
}
