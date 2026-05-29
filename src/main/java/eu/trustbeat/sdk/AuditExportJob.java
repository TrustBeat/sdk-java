package eu.trustbeat.sdk;

/** Returned immediately (202) when an audit export job is created. */
public final class AuditExportJob {
    private final String  jobId;
    private final String  status;
    private final Integer eventCount;
    private final String  error;

    public AuditExportJob(String jobId, String status, Integer eventCount, String error) {
        this.jobId      = jobId;
        this.status     = status;
        this.eventCount = eventCount;
        this.error      = error;
    }

    public String  getJobId()      { return jobId; }
    /** "pending" | "processing" | "ready" | "failed" */
    public String  getStatus()     { return status; }
    /** Number of events in the export; null while still processing. */
    public Integer getEventCount() { return eventCount; }
    /** Error message if status is "failed"; null otherwise. */
    public String  getError()      { return error; }

    @Override public String toString() {
        return "AuditExportJob{jobId=" + jobId + ", status=" + status + "}";
    }
}
