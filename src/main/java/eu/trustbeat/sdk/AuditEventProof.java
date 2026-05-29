package eu.trustbeat.sdk;

import java.util.List;

/** Full Merkle inclusion proof for an anchored audit event. */
public final class AuditEventProof {
    private final String              eventId;
    private final String              canonicalHash;
    private final String              batchId;
    private final int                 leafIndex;
    private final List<AuditProofStep> merklePath;
    private final String              anchoredAt;

    public AuditEventProof(String eventId, String canonicalHash, String batchId,
                           int leafIndex, List<AuditProofStep> merklePath, String anchoredAt) {
        this.eventId       = eventId;
        this.canonicalHash = canonicalHash;
        this.batchId       = batchId;
        this.leafIndex     = leafIndex;
        this.merklePath    = merklePath;
        this.anchoredAt    = anchoredAt;
    }

    public String               getEventId()       { return eventId; }
    public String               getCanonicalHash() { return canonicalHash; }
    public String               getBatchId()       { return batchId; }
    public int                  getLeafIndex()     { return leafIndex; }
    public List<AuditProofStep> getMerklePath()    { return merklePath; }
    /** ISO 8601 timestamp of when the batch was anchored. */
    public String               getAnchoredAt()    { return anchoredAt; }

    @Override public String toString() {
        return "AuditEventProof{eventId=" + eventId + ", batchId=" + batchId + ", leafIndex=" + leafIndex + "}";
    }
}
