package eu.trustbeat.sdk;

/** Lightweight status of a log anchor submission. */
public final class LogStatus {
    private final String id;
    private final String status;
    private final String submittedAt;
    private final String anchoredAt;

    public LogStatus(String id, String status, String submittedAt, String anchoredAt) {
        this.id = id; this.status = status; this.submittedAt = submittedAt; this.anchoredAt = anchoredAt;
    }

    public String getId()          { return id; }
    public String getStatus()      { return status; }
    public String getSubmittedAt() { return submittedAt; }
    /** ISO 8601 anchor time, or null until anchored. */
    public String getAnchoredAt()  { return anchoredAt; }
}
