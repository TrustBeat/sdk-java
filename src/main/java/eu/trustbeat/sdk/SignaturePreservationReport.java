package eu.trustbeat.sdk;

import java.util.List;
import java.util.Map;

/**
 * The report of {@code POST /v1/signature-preservation/{id}/verify}.
 * <p>
 * {@link #getResult()} is {@code "passed"}, {@code "failed"} (a step failed) or {@code "indeterminate"}
 * (a step could not be decided). {@link #getRaw()} is the full JSON report (signatures now and at
 * preservation, evidence-record time-stamps).
 */
public final class SignaturePreservationReport {

    /** One step of the report. */
    public static final class Step {
        private final int step;
        private final String name, title, result;
        private final List<String> checkedBy, details;

        public Step(int step, String name, String title, String result, List<String> checkedBy, List<String> details) {
            this.step = step; this.name = name; this.title = title; this.result = result;
            this.checkedBy = checkedBy; this.details = details;
        }

        public int getStep()              { return step; }
        /** file, binding, signature, chain, timestamps, qualification or evidence-record. */
        public String getName()           { return name; }
        public String getTitle()          { return title; }
        /** passed, failed, indeterminate or not-applicable. */
        public String getResult()         { return result; }
        public List<String> getCheckedBy() { return checkedBy; }
        public List<String> getDetails()  { return details; }
    }

    private final String recordId, result, claim;
    private final List<Step> steps;
    private final Map<String, Object> raw;

    public SignaturePreservationReport(String recordId, String result, String claim, List<Step> steps, Map<String, Object> raw) {
        this.recordId = recordId; this.result = result; this.claim = claim; this.steps = steps; this.raw = raw;
    }

    public String getRecordId()        { return recordId; }
    public String getResult()          { return result; }
    public String getClaim()           { return claim; }
    public List<Step> getSteps()       { return steps; }
    public Map<String, Object> getRaw() { return raw; }
}
