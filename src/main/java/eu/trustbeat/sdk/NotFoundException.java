package eu.trustbeat.sdk;

/** 404 — tracking ID not found (or not yet anchored — check getCode() for "NOT_ANCHORED"). */
public class NotFoundException extends TrustBeatException {
    public NotFoundException(String message) {
        super(message, 404, "NOT_FOUND");
    }

    public NotFoundException(String message, String code) {
        super(message, 404, code);
    }
}
