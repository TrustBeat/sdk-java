package eu.trustbeat.sdk;

/** A single audit event as returned by the list endpoint. */
public final class AuditEvent {
    private final String  eventId;
    private final String  trailCategory;
    private final String  actor;
    private final String  action;
    private final String  ts;
    private final String  receivedAt;
    private final boolean anchored;
    private final String  system;
    private final String  resource;

    public AuditEvent(String eventId, String trailCategory, String actor, String action,
                      String ts, String receivedAt, boolean anchored, String system, String resource) {
        this.eventId       = eventId;
        this.trailCategory = trailCategory;
        this.actor         = actor;
        this.action        = action;
        this.ts            = ts;
        this.receivedAt    = receivedAt;
        this.anchored      = anchored;
        this.system        = system;
        this.resource      = resource;
    }

    public String  getEventId()       { return eventId; }
    public String  getTrailCategory() { return trailCategory; }
    public String  getActor()         { return actor; }
    public String  getAction()        { return action; }
    /** ISO 8601 timestamp of when the event occurred. */
    public String  getTs()            { return ts; }
    /** ISO 8601 timestamp of when TrustBeat received the event. */
    public String  getReceivedAt()    { return receivedAt; }
    public boolean isAnchored()       { return anchored; }
    public String  getSystem()        { return system; }
    public String  getResource()      { return resource; }

    @Override public String toString() {
        return "AuditEvent{eventId=" + eventId + ", action=" + action + ", anchored=" + anchored + "}";
    }
}
