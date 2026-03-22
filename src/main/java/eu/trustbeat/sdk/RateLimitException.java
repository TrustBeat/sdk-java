package eu.trustbeat.sdk;

/** 429 — too many requests. */
public class RateLimitException extends TrustBeatException {
    public RateLimitException(String message) {
        super(message, 429, "RATE_LIMITED");
    }
}
