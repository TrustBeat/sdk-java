package eu.trustbeat.sdk;

import java.util.List;
import java.util.Map;

/**
 * A preserved signed file ({@code /v1/signature-preservation}).
 * <p>
 * {@link #getStatus()} is {@code "pending"} (queued for the next anchoring cycle), {@code "anchored"}
 * (its RFC 4998 evidence record is being made) or {@code "preserved"} (the evidence record exists).
 * {@link #getSignatures()} is {@code null} in a list; each entry is the API's object (signer, EU DSS
 * indication, qualification).
 */
public final class SignaturePreservationRecord {
    private final String id, status, createdAt, clientRef;
    private final String containerFormat, containerName, containerSha256;
    private final int signatureCount;
    private final String peoSha256, profile, preserveUntil, evidenceRecordStatus, evidenceRecordUrl;
    private final List<Map<String, Object>> signatures;

    public SignaturePreservationRecord(String id, String status, String createdAt, String clientRef,
                                       String containerFormat, String containerName, String containerSha256,
                                       int signatureCount, String peoSha256, String profile, String preserveUntil,
                                       String evidenceRecordStatus, String evidenceRecordUrl,
                                       List<Map<String, Object>> signatures) {
        this.id = id; this.status = status; this.createdAt = createdAt; this.clientRef = clientRef;
        this.containerFormat = containerFormat; this.containerName = containerName; this.containerSha256 = containerSha256;
        this.signatureCount = signatureCount; this.peoSha256 = peoSha256; this.profile = profile;
        this.preserveUntil = preserveUntil; this.evidenceRecordStatus = evidenceRecordStatus;
        this.evidenceRecordUrl = evidenceRecordUrl; this.signatures = signatures;
    }

    public String getId()                   { return id; }
    public String getStatus()               { return status; }
    public String getCreatedAt()            { return createdAt; }
    /** Your own reference, or {@code null}. */
    public String getClientRef()            { return clientRef; }
    /** PAdES, XAdES, CAdES, ASiC-E or ASiC-S. */
    public String getContainerFormat()      { return containerFormat; }
    public String getContainerName()        { return containerName; }
    public String getContainerSha256()      { return containerSha256; }
    public int    getSignatureCount()       { return signatureCount; }
    /** SHA-256 of the Preservation Evidence Object — the anchored leaf. */
    public String getPeoSha256()            { return peoSha256; }
    public String getProfile()              { return profile; }
    public String getPreserveUntil()        { return preserveUntil; }
    /** {@code "pending"} or {@code "ready"}. */
    public String getEvidenceRecordStatus() { return evidenceRecordStatus; }
    /** Download URL of the evidence record once ready, else {@code null}. */
    public String getEvidenceRecordUrl()    { return evidenceRecordUrl; }
    public List<Map<String, Object>> getSignatures() { return signatures; }
}
