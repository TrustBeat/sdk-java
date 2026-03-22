package eu.trustbeat.sdk;

/** One step in a Merkle inclusion proof path. */
public final class ProofStep {

    private final String sibling;
    private final String side;

    public ProofStep(String sibling, String side) {
        this.sibling = sibling;
        this.side    = side;
    }

    /** Hex-encoded SHA-256 hash of the sibling node. */
    public String getSibling() { return sibling; }

    /** Position of the sibling relative to the current node: "left" or "right". */
    public String getSide()    { return side; }

    @Override
    public String toString() {
        return "ProofStep{sibling='" + sibling + "', side='" + side + "'}";
    }
}
