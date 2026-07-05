package eu.trustbeat.sdk;

/** Time window covered by an anchored log. */
public final class LogTimeEnvelope {
    private final String startAt;
    private final String endAt;

    public LogTimeEnvelope(String startAt, String endAt) {
        this.startAt = startAt;
        this.endAt   = endAt;
    }

    /** ISO 8601 start of the log window. */
    public String getStartAt() { return startAt; }
    /** ISO 8601 end of the log window. */
    public String getEndAt()   { return endAt; }
}
