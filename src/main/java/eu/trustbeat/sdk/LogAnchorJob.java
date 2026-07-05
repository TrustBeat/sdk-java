package eu.trustbeat.sdk;

/** Returned immediately (202) when a log hash is enqueued for anchoring. */
public final class LogAnchorJob {
    private final String  id;
    private final String  logHash;
    private final String  combinedHash;
    private final String  status;
    private final String  submittedAt;
    private final boolean overage;
    private final String  label;

    public LogAnchorJob(String id, String logHash, String combinedHash, String status,
                        String submittedAt, boolean overage, String label) {
        this.id = id; this.logHash = logHash; this.combinedHash = combinedHash;
        this.status = status; this.submittedAt = submittedAt; this.overage = overage; this.label = label;
    }

    public String  getId()           { return id; }
    public String  getLogHash()      { return logHash; }
    public String  getCombinedHash() { return combinedHash; }
    public String  getStatus()       { return status; }
    public String  getSubmittedAt()  { return submittedAt; }
    public boolean isOverage()       { return overage; }
    public String  getLabel()        { return label; }
}
