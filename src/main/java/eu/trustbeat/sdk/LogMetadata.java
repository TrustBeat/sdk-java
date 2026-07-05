package eu.trustbeat.sdk;

/**
 * Metadata sealed alongside a log hash for NIS2 Article 21 anchoring.
 *
 * <p>The server computes {@code combined_hash = SHA-256(log_hash_bytes ‖ UTF-8(JCS(metadata)))},
 * binding this context into the Merkle leaf. {@code logSource} and {@code sourceIdentity} are
 * required; {@code timeEnvelope} is optional.
 */
public final class LogMetadata {
    private final LogSource        logSource;
    private final LogSourceIdentity sourceIdentity;
    private final LogTimeEnvelope   timeEnvelope;

    private LogMetadata(Builder b) {
        this.logSource      = b.logSource;
        this.sourceIdentity = b.sourceIdentity;
        this.timeEnvelope   = b.timeEnvelope;
    }

    public LogSource         getLogSource()      { return logSource; }
    public LogSourceIdentity getSourceIdentity() { return sourceIdentity; }
    public LogTimeEnvelope   getTimeEnvelope()   { return timeEnvelope; }

    public static final class Builder {
        private LogSource        logSource;
        private LogSourceIdentity sourceIdentity;
        private LogTimeEnvelope   timeEnvelope;
        public Builder logSource(LogSource v)             { this.logSource = v; return this; }
        public Builder sourceIdentity(LogSourceIdentity v){ this.sourceIdentity = v; return this; }
        public Builder timeEnvelope(LogTimeEnvelope v)    { this.timeEnvelope = v; return this; }
        public LogMetadata build()                        { return new LogMetadata(this); }
    }
}
