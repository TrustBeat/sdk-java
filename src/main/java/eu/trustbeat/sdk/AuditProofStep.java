package eu.trustbeat.sdk;

/** One step in an audit event Merkle inclusion proof. */
public final class AuditProofStep {
    private final String sibling;
    private final String side;

    public AuditProofStep(String sibling, String side) {
        this.sibling = sibling;
        this.side    = side;
    }

    /** Hex-encoded SHA-256 hash of the sibling node. */
    public String getSibling() { return sibling; }

    /** Position of the sibling: "left" or "right". */
    public String getSide() { return side; }

    @Override public String toString() {
        return "AuditProofStep{side=" + side + ", sibling=" + sibling.substring(0, Math.min(16, sibling.length())) + "…}";
    }
}
