package eu.trustbeat.sdk;

/** Time window of a single AI inference call. */
public final class AiTimeEnvelope {
    private final String startedAt;
    private final String completedAt;

    public AiTimeEnvelope(String startedAt, String completedAt) {
        this.startedAt   = startedAt;
        this.completedAt = completedAt;
    }

    /** ISO 8601 timestamp when inference started. */
    public String getStartedAt()   { return startedAt; }
    /** ISO 8601 timestamp when inference completed. */
    public String getCompletedAt() { return completedAt; }
}
