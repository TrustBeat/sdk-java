package eu.trustbeat.sdk;

import java.time.Duration;

/**
 * 429 — too many requests.
 *
 * <p>The client already retries a 429 automatically (see {@link TrustBeat.Builder#maxRetries});
 * this is thrown once those retries are spent. A refused submission was not queued, so retrying
 * it can never anchor a hash twice.
 */
public class RateLimitException extends TrustBeatException {

    private final Duration retryAfter;

    public RateLimitException(String message) {
        this(message, null);
    }

    public RateLimitException(String message, Duration retryAfter) {
        super(message, 429, "RATE_LIMITED");
        this.retryAfter = retryAfter;
    }

    /** How long the server asked to wait before the next attempt ({@code Retry-After}), or null if it sent none. */
    public Duration getRetryAfter() { return retryAfter; }
}
