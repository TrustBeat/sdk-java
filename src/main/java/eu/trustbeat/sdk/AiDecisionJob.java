package eu.trustbeat.sdk;

/**
 * Returned immediately (HTTP 202) when an AI decision is enqueued for anchoring.
 * Use {@link TrustBeat#anchorAiDecisionWait(String)} to block until the proof is ready.
 */
public final class AiDecisionJob {
    private final String  id;
    private final String  inputHash;
    private final String  outputHash;
    private final String  combinedHash;
    private final String  status;
    private final String  submittedAt;
    private final boolean overage;

    public AiDecisionJob(String id, String inputHash, String outputHash,
                         String combinedHash, String status,
                         String submittedAt, boolean overage) {
        this.id           = id;
        this.inputHash    = inputHash;
        this.outputHash   = outputHash;
        this.combinedHash = combinedHash;
        this.status       = status;
        this.submittedAt  = submittedAt;
        this.overage      = overage;
    }

    public String  getId()           { return id; }
    public String  getInputHash()    { return inputHash; }
    public String  getOutputHash()   { return outputHash; }
    /** SHA-256(input_bytes ‖ output_bytes ‖ UTF-8(JCS(metadata))) */
    public String  getCombinedHash() { return combinedHash; }
    public String  getStatus()       { return status; }
    public String  getSubmittedAt()  { return submittedAt; }
    /** True when the monthly anchor quota was already exceeded. */
    public boolean isOverage()       { return overage; }
}
