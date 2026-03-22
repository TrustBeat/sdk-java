package eu.trustbeat.sdk;

/** 401 — invalid or missing API key. */
public class AuthException extends TrustBeatException {
    public AuthException(String message) {
        super(message, 401, "UNAUTHORIZED");
    }
}
