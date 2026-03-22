package eu.trustbeat.sdk;

/**
 * Represents a pending or completed anchoring job.
 * Returned by {@link TrustBeat#anchor} and {@link TrustBeat#anchorBatch}.
 */
public final class AnchorJob {

    private final String  id;
    private final String  hash;
    private final String  hashAlgorithm;
    private final String  status;
    private final String  submittedAt;
    private final boolean overage;

    public AnchorJob(String id, String hash, String hashAlgorithm,
                     String status, String submittedAt, boolean overage) {
        this.id            = id;
        this.hash          = hash;
        this.hashAlgorithm = hashAlgorithm;
        this.status        = status;
        this.submittedAt   = submittedAt;
        this.overage       = overage;
    }

    public String  getId()            { return id; }
    public String  getHash()          { return hash; }
    public String  getHashAlgorithm() { return hashAlgorithm; }
    public String  getStatus()        { return status; }
    public String  getSubmittedAt()   { return submittedAt; }
    public boolean isOverage()        { return overage; }

    @Override
    public String toString() {
        return "AnchorJob{id='" + id + "', status='" + status + "', overage=" + overage + "}";
    }
}
