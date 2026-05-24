package eu.trustbeat.sdk;

/**
 * Returned by {@link TrustBeat#getBatchStatus} — shows anchored/pending counts for a submission.
 */
public final class BatchStatus {

    private final String submissionId;
    private final int    total;
    private final int    anchored;
    private final int    pending;

    public BatchStatus(String submissionId, int total, int anchored, int pending) {
        this.submissionId = submissionId;
        this.total        = total;
        this.anchored     = anchored;
        this.pending      = pending;
    }

    public String getSubmissionId() { return submissionId; }
    public int    getTotal()        { return total; }
    public int    getAnchored()     { return anchored; }
    public int    getPending()      { return pending; }

    @Override
    public String toString() {
        return "BatchStatus{submissionId='" + submissionId + "', total=" + total
            + ", anchored=" + anchored + ", pending=" + pending + "}";
    }
}
