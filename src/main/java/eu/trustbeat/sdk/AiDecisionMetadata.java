package eu.trustbeat.sdk;

/**
 * Metadata describing an AI decision for EU AI Act Article 12 anchoring.
 *
 * <p>Build with the inner {@link Builder}:
 * <pre>{@code
 * AiDecisionMetadata meta = new AiDecisionMetadata.Builder()
 *     .modelId("claude-3-5-sonnet-20241022")
 *     .systemName("cv-screening-v2")
 *     .riskCategory("employment")
 *     .decisionType("classification")
 *     .humanOversight(true)
 *     .timeEnvelope(new AiTimeEnvelope("2026-04-15T10:00:00Z", "2026-04-15T10:00:00.250Z"))
 *     .build();
 * }</pre>
 */
public final class AiDecisionMetadata {
    private final String         modelId;
    private final String         modelVersion;
    private final String         systemName;
    private final String         riskCategory;
    private final String         decisionType;
    private final boolean        humanOversight;
    private final AiTimeEnvelope timeEnvelope;
    private final String         operatorId;
    private final String         deploymentEnv;

    private AiDecisionMetadata(Builder b) {
        this.modelId        = b.modelId;
        this.modelVersion   = b.modelVersion;
        this.systemName     = b.systemName;
        this.riskCategory   = b.riskCategory;
        this.decisionType   = b.decisionType;
        this.humanOversight = b.humanOversight;
        this.timeEnvelope   = b.timeEnvelope;
        this.operatorId     = b.operatorId;
        this.deploymentEnv  = b.deploymentEnv;
    }

    public String         getModelId()        { return modelId; }
    public String         getModelVersion()   { return modelVersion; }
    public String         getSystemName()     { return systemName; }
    public String         getRiskCategory()   { return riskCategory; }
    public String         getDecisionType()   { return decisionType; }
    public boolean        isHumanOversight()  { return humanOversight; }
    public AiTimeEnvelope getTimeEnvelope()   { return timeEnvelope; }
    public String         getOperatorId()     { return operatorId; }
    public String         getDeploymentEnv()  { return deploymentEnv; }

    public static final class Builder {
        private String         modelId;
        private String         modelVersion;
        private String         systemName;
        private String         riskCategory;
        private String         decisionType;
        private boolean        humanOversight;
        private AiTimeEnvelope timeEnvelope;
        private String         operatorId;
        private String         deploymentEnv;

        public Builder modelId(String v)           { this.modelId        = v; return this; }
        public Builder modelVersion(String v)      { this.modelVersion   = v; return this; }
        public Builder systemName(String v)        { this.systemName     = v; return this; }
        public Builder riskCategory(String v)      { this.riskCategory   = v; return this; }
        public Builder decisionType(String v)      { this.decisionType   = v; return this; }
        public Builder humanOversight(boolean v)   { this.humanOversight = v; return this; }
        public Builder timeEnvelope(AiTimeEnvelope v) { this.timeEnvelope = v; return this; }
        public Builder operatorId(String v)        { this.operatorId     = v; return this; }
        public Builder deploymentEnv(String v)     { this.deploymentEnv  = v; return this; }

        public AiDecisionMetadata build() {
            if (modelId == null || modelId.isEmpty())
                throw new IllegalArgumentException("modelId must not be empty");
            if (systemName == null || systemName.isEmpty())
                throw new IllegalArgumentException("systemName must not be empty");
            if (riskCategory == null || riskCategory.isEmpty())
                throw new IllegalArgumentException("riskCategory must not be empty");
            if (decisionType == null || decisionType.isEmpty())
                throw new IllegalArgumentException("decisionType must not be empty");
            if (timeEnvelope == null)
                throw new IllegalArgumentException("timeEnvelope must not be null");
            return new AiDecisionMetadata(this);
        }
    }
}
