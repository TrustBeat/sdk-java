package eu.trustbeat.sdk;

/** 402 — monthly quota exceeded. */
public class QuotaException extends TrustBeatException {
    public QuotaException(String message) {
        super(message, 402, "QUOTA_EXCEEDED");
    }
}
