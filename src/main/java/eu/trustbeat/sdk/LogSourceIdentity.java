package eu.trustbeat.sdk;

/** Identity of the system that emitted the log (all fields optional). */
public final class LogSourceIdentity {
    private final String systemUuid;
    private final String cloudInstanceId;
    private final String hostname;
    private final String serviceName;
    private final String tenantId;

    private LogSourceIdentity(Builder b) {
        this.systemUuid      = b.systemUuid;
        this.cloudInstanceId = b.cloudInstanceId;
        this.hostname        = b.hostname;
        this.serviceName     = b.serviceName;
        this.tenantId        = b.tenantId;
    }

    public String getSystemUuid()      { return systemUuid; }
    public String getCloudInstanceId() { return cloudInstanceId; }
    public String getHostname()        { return hostname; }
    public String getServiceName()     { return serviceName; }
    public String getTenantId()        { return tenantId; }

    public static final class Builder {
        private String systemUuid, cloudInstanceId, hostname, serviceName, tenantId;
        public Builder systemUuid(String v)      { this.systemUuid = v; return this; }
        public Builder cloudInstanceId(String v) { this.cloudInstanceId = v; return this; }
        public Builder hostname(String v)        { this.hostname = v; return this; }
        public Builder serviceName(String v)     { this.serviceName = v; return this; }
        public Builder tenantId(String v)        { this.tenantId = v; return this; }
        public LogSourceIdentity build()         { return new LogSourceIdentity(this); }
    }
}
