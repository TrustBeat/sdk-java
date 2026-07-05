package eu.trustbeat.sdk;

/** Identifies the log source being anchored. URI is required; name and sizeBytes optional. */
public final class LogSource {
    private final String uri;
    private final String name;
    private final Long   sizeBytes;

    private LogSource(Builder b) { this.uri = b.uri; this.name = b.name; this.sizeBytes = b.sizeBytes; }

    /** Convenience constructor for a source identified only by URI. */
    public LogSource(String uri) { this.uri = uri; this.name = null; this.sizeBytes = null; }

    public String getUri()       { return uri; }
    public String getName()      { return name; }
    /** Size of the log file/stream in bytes, or null if unset. */
    public Long   getSizeBytes() { return sizeBytes; }

    public static final class Builder {
        private String uri;
        private String name;
        private Long   sizeBytes;
        public Builder uri(String v)     { this.uri = v; return this; }
        public Builder name(String v)    { this.name = v; return this; }
        public Builder sizeBytes(long v) { this.sizeBytes = v; return this; }
        public LogSource build()         { return new LogSource(this); }
    }
}
