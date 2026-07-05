package eu.trustbeat.sdk;

/** A single log anchor submission as returned by listLogs(). */
public final class LogAnchorListItem {
    private final String id;
    private final String logHash;
    private final String status;
    private final String submittedAt;
    private final String logSourceUri;
    private final String anchoredAt;
    private final String serviceName;
    private final String label;

    public LogAnchorListItem(String id, String logHash, String status, String submittedAt,
                             String logSourceUri, String anchoredAt, String serviceName, String label) {
        this.id = id; this.logHash = logHash; this.status = status; this.submittedAt = submittedAt;
        this.logSourceUri = logSourceUri; this.anchoredAt = anchoredAt; this.serviceName = serviceName; this.label = label;
    }

    public String getId()           { return id; }
    public String getLogHash()      { return logHash; }
    public String getStatus()       { return status; }
    public String getSubmittedAt()  { return submittedAt; }
    public String getLogSourceUri() { return logSourceUri; }
    public String getAnchoredAt()   { return anchoredAt; }
    public String getServiceName()  { return serviceName; }
    public String getLabel()        { return label; }
}
