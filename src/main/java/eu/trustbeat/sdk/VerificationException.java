package eu.trustbeat.sdk;

/** Raised when local Merkle proof verification encounters malformed data. */
public class VerificationException extends TrustBeatException {
    public VerificationException(String message) {
        super(message);
    }
}
