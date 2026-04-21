package eu.trustbeat.sdk;

/**
 * Returned immediately (HTTP 202) when
 * {@link TrustBeat#verifyAndAnchor(byte[], String)} is called.
 * Use {@link TrustBeat#getVerification(String)} to retrieve the completed report.
 */
public final class VerificationJob {
    private final String trackingId;
    private final String documentHash;
    private final String status;
    private final String submittedAt;

    public VerificationJob(String trackingId, String documentHash,
                            String status, String submittedAt) {
        this.trackingId   = trackingId;
        this.documentHash = documentHash;
        this.status       = status;
        this.submittedAt  = submittedAt;
    }

    public String getTrackingId()   { return trackingId; }
    public String getDocumentHash() { return documentHash; }
    public String getStatus()       { return status; }
    public String getSubmittedAt()  { return submittedAt; }
}
