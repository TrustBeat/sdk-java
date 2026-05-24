package eu.trustbeat.sdk;

import java.util.List;

/**
 * Returned by {@link TrustBeat#anchorBatch} — groups all submitted items under a single
 * {@code submissionId} for batch status polling and proof retrieval.
 */
public final class BatchSubmission {

    private final String          submissionId;
    private final List<AnchorJob> items;

    public BatchSubmission(String submissionId, List<AnchorJob> items) {
        this.submissionId = submissionId;
        this.items        = items;
    }

    public String          getSubmissionId() { return submissionId; }
    public List<AnchorJob> getItems()        { return items; }

    @Override
    public String toString() {
        return "BatchSubmission{submissionId='" + submissionId + "', items=" + items.size() + "}";
    }
}
