package eu.trustbeat.sdk;

/**
 * Verification result returned once an AI decision has been anchored.
 *
 * <p>{@code getVerificationStatus()} returns {@code "VERIFIED"} when the Merkle
 * proof is cryptographically valid and the combined hash in the leaf matches the
 * expected value.  {@code getProof()} contains the full Merkle inclusion proof
 * with the qualified RFC 3161 token.
 */
public final class AiDecisionProof {
    private final String             id;
    private final String             inputHash;
    private final String             outputHash;
    private final String             combinedHash;
    private final AiDecisionMetadata metadata;
    private final String             verificationStatus;
    private final String             anchoredAt;
    private final AnchorProof        proof;

    public AiDecisionProof(String id, String inputHash, String outputHash,
                           String combinedHash, AiDecisionMetadata metadata,
                           String verificationStatus, String anchoredAt,
                           AnchorProof proof) {
        this.id                 = id;
        this.inputHash          = inputHash;
        this.outputHash         = outputHash;
        this.combinedHash       = combinedHash;
        this.metadata           = metadata;
        this.verificationStatus = verificationStatus;
        this.anchoredAt         = anchoredAt;
        this.proof              = proof;
    }

    public String             getId()                 { return id; }
    public String             getInputHash()          { return inputHash; }
    public String             getOutputHash()         { return outputHash; }
    public String             getCombinedHash()       { return combinedHash; }
    public AiDecisionMetadata getMetadata()           { return metadata; }
    /** "VERIFIED" or "FAILED" */
    public String             getVerificationStatus() { return verificationStatus; }
    /** ISO 8601 timestamp, or null if not available. */
    public String             getAnchoredAt()         { return anchoredAt; }
    /** Full Merkle inclusion proof including the qualified RFC 3161 token. */
    public AnchorProof        getProof()              { return proof; }
}
