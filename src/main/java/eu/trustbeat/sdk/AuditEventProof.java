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
    private final String              merkleRoot;
    private final Integer             treeSize;
    private final String              merkleAlgorithm;

    /**
     * Pre-1.46 shape, kept for source compatibility. Leaves {@code merkleRoot}
     * and {@code treeSize} null and the algorithm legacy, which is exactly what
     * an older server sends.
     */
    public AuditEventProof(String eventId, String canonicalHash, String batchId,
                           int leafIndex, List<AuditProofStep> merklePath, String anchoredAt) {
        this(eventId, canonicalHash, batchId, leafIndex, merklePath, anchoredAt,
             null, null, MerkleAlgorithm.LEGACY_SHA256);
    }

    public AuditEventProof(String eventId, String canonicalHash, String batchId,
                           int leafIndex, List<AuditProofStep> merklePath, String anchoredAt,
                           String merkleRoot, Integer treeSize, String merkleAlgorithm) {
        this.eventId       = eventId;
        this.canonicalHash = canonicalHash;
        this.batchId       = batchId;
        this.leafIndex     = leafIndex;
        this.merklePath    = merklePath;
        this.anchoredAt    = anchoredAt;
        this.merkleRoot    = merkleRoot;
        this.treeSize      = treeSize;
        this.merkleAlgorithm = (merkleAlgorithm == null || merkleAlgorithm.isEmpty())
            ? MerkleAlgorithm.LEGACY_SHA256 : merkleAlgorithm;
    }

    public String               getEventId()       { return eventId; }
    public String               getCanonicalHash() { return canonicalHash; }
    public String               getBatchId()       { return batchId; }
    public int                  getLeafIndex()     { return leafIndex; }
    public List<AuditProofStep> getMerklePath()    { return merklePath; }
    /** ISO 8601 timestamp of when the batch was anchored. */
    public String               getAnchoredAt()    { return anchoredAt; }
    /**
     * Root of the batch — the value the RFC 3161 token covers.
     * {@code null} from servers older than API 1.46, which did not send it;
     * that is what makes a proof unverifiable locally.
     */
    public String               getMerkleRoot()    { return merkleRoot; }
    /** Leaves in the batch. {@code null} from servers older than API 1.46. */
    public Integer              getTreeSize()      { return treeSize; }
    /** How {@code merklePath} must be folded. Legacy when the server did not say. */
    public String               getMerkleAlgorithm() { return merkleAlgorithm; }

    @Override public String toString() {
        return "AuditEventProof{eventId=" + eventId + ", batchId=" + batchId + ", leafIndex=" + leafIndex + "}";
    }
}
