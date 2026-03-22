package eu.trustbeat.sdk;

/** 404 — tracking ID not found. */
public class NotFoundException extends TrustBeatException {
    public NotFoundException(String message) {
        super(message, 404, "NOT_FOUND");
    }
}
