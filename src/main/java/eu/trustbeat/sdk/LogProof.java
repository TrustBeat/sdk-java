package eu.trustbeat.sdk;

import java.util.List;

/**
 * Verification result for an anchored log. verificationStatus is "VERIFIED" when the
 * Merkle proof is valid and the combined hash matches; proof is null otherwise.
 */
public final class LogProof {
    private final String       id;
    private final String       logHash;
    private final LogMetadata  metadata;
    private final String       combinedHash;
    private final String       verificationStatus;
    private final int          archiveStampsCount;
    private final String       anchoredAt;
    private final AnchorProof  proof;
    private final List<String> failureReasons;

    public LogProof(String id, String logHash, LogMetadata metadata, String combinedHash,
                    String verificationStatus, int archiveStampsCount, String anchoredAt,
                    AnchorProof proof, List<String> failureReasons) {
        this.id = id; this.logHash = logHash; this.metadata = metadata; this.combinedHash = combinedHash;
        this.verificationStatus = verificationStatus; this.archiveStampsCount = archiveStampsCount;
        this.anchoredAt = anchoredAt; this.proof = proof; this.failureReasons = failureReasons;
    }

    public String       getId()                 { return id; }
    public String       getLogHash()            { return logHash; }
    public LogMetadata  getMetadata()           { return metadata; }
    public String       getCombinedHash()       { return combinedHash; }
    public String       getVerificationStatus() { return verificationStatus; }
    public int          getArchiveStampsCount() { return archiveStampsCount; }
    public String       getAnchoredAt()         { return anchoredAt; }
    public AnchorProof  getProof()              { return proof; }
    public List<String> getFailureReasons()     { return failureReasons; }
}
