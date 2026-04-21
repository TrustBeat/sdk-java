package eu.trustbeat.sdk;

import java.util.List;

/**
 * Full eIDAS signature verification report returned by
 * {@link TrustBeat#verifySignature(byte[], String)}.
 * <p>
 * {@code verdict} is the top-level result (worst verdict across all signatures).
 * {@code trackingId} is set after the report is saved; use with
 * {@link TrustBeat#getVerification(String)}.
 */
public final class VerificationReport {
    private final String              verdict;
    private final List<SignatureDetail> signatures;
    private final String              documentHash;
    private final String              checkedAt;
    private final String              eutlVersion;
    private final String              trackingId;

    public VerificationReport(String verdict, List<SignatureDetail> signatures,
                               String documentHash, String checkedAt,
                               String eutlVersion, String trackingId) {
        this.verdict      = verdict;
        this.signatures   = signatures;
        this.documentHash = documentHash;
        this.checkedAt    = checkedAt;
        this.eutlVersion  = eutlVersion;
        this.trackingId   = trackingId;
    }

    public String               getVerdict()      { return verdict; }
    public List<SignatureDetail> getSignatures()   { return signatures; }
    public String               getDocumentHash() { return documentHash; }
    public String               getCheckedAt()    { return checkedAt; }
    public String               getEutlVersion()  { return eutlVersion; }
    public String               getTrackingId()   { return trackingId; }
}
