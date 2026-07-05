package eu.trustbeat.sdk;

import eu.trustbeat.sdk.internal.ApiClient;
import eu.trustbeat.sdk.internal.Json;
import eu.trustbeat.sdk.internal.MerkleVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * TrustBeat SDK client.
 *
 * <pre>{@code
 * TrustBeat client = new TrustBeat.Builder()
 *     .apiKey("tb_live_...")
 *     .build();
 *
 * AnchorJob job   = client.anchor("abc...64hex");
 * AnchorProof proof = client.anchorWait(job.getId());
 * boolean valid   = client.verify(proof);
 * }</pre>
 *
 * Zero runtime dependencies — uses java.net.http (Java 11+) and java.security.
 */
public final class TrustBeat {

    static final String DEFAULT_BASE_URL = "https://api.trustbeat.eu/v1";

    private final ApiClient http;

    private TrustBeat(Builder builder) {
        this.http = new ApiClient(builder.apiKey, builder.baseUrl,
                                  Duration.ofMillis(builder.connectTimeoutMs));
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    public static final class Builder {
        private String  apiKey;
        private String  baseUrl           = DEFAULT_BASE_URL;
        private long    connectTimeoutMs  = 10_000;

        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder connectTimeoutMs(long ms) {
            this.connectTimeoutMs = ms;
            return this;
        }

        public TrustBeat build() {
            if (apiKey == null || apiKey.isEmpty())
                throw new IllegalArgumentException("apiKey must not be empty");
            return new TrustBeat(this);
        }
    }

    // ── Options ───────────────────────────────────────────────────────────────

    public static final class AnchorOptions {
        private String clientRef;
        private String description;

        public AnchorOptions clientRef(String ref)    { this.clientRef = ref; return this; }
        public AnchorOptions description(String desc) { this.description = desc; return this; }
        String getClientRef()   { return clientRef; }
        String getDescription() { return description; }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Submit a SHA-256 hash for anchoring.
     * Use {@link #anchorWait} to block until the proof is ready.
     */
    public AnchorJob anchor(String hash) {
        return anchor(hash, new AnchorOptions());
    }

    public AnchorJob anchor(String hash, AnchorOptions options) {
        String body = Json.buildObject(
            "hash",           hash,
            "hash_algorithm", "SHA-256",
            "client_ref",     options.getClientRef(),
            "description",    options.getDescription()
        );
        Map<String, Object> data = http.post("/anchor", body);
        return ApiClient.parseAnchorJob(data);
    }

    /**
     * Submit up to 100 SHA-256 hashes in a single batch request.
     * Returns a {@link BatchSubmission} grouping all items under a single submissionId.
     * Use {@link #anchorBatchWait(BatchSubmission)} to block until all proofs are ready.
     */
    public BatchSubmission anchorBatch(List<String> hashes) {
        return anchorBatch(hashes, new AnchorOptions());
    }

    public BatchSubmission anchorBatch(List<String> hashes, AnchorOptions options) {
        if (hashes.isEmpty()) return new BatchSubmission("", new ArrayList<>());
        if (hashes.size() > 100)
            throw new IllegalArgumentException("anchorBatch: maximum 100 hashes per request");

        StringBuilder items = new StringBuilder("[");
        for (int i = 0; i < hashes.size(); i++) {
            if (i > 0) items.append(",");
            items.append(Json.buildObject("hash", hashes.get(i), "hash_algorithm", "SHA-256"));
        }
        items.append("]");

        // Build the body directly: `items` is already a JSON array, so it must be
        // spliced in raw (not as an escaped JSON string). Optional string fields are
        // appended via Json.buildObject (reusing its escaping) with the braces stripped.
        StringBuilder body = new StringBuilder("{\"hashes\":").append(items);
        if (options.getClientRef() != null) {
            String o = Json.buildObject("client_ref", options.getClientRef());
            body.append(",").append(o, 1, o.length() - 1);
        }
        if (options.getDescription() != null) {
            String o = Json.buildObject("description", options.getDescription());
            body.append(",").append(o, 1, o.length() - 1);
        }
        body.append("}");

        Map<String, Object> data = http.post("/anchor/batch", body.toString());
        String submissionId = Json.str(data, "submission_id");
        if (submissionId == null) submissionId = "";
        List<AnchorJob> jobs = new ArrayList<>();
        for (Map<String, Object> item : Json.array(data, "accepted")) {
            jobs.add(ApiClient.parseAnchorJob(item));
        }
        return new BatchSubmission(submissionId, jobs);
    }

    /**
     * Return anchored/pending counts for a batch submission.
     *
     * @param submissionId the ID returned by {@link #anchorBatch}
     */
    public BatchStatus getBatchStatus(String submissionId) {
        String path = "/anchor/batch/" + URLEncoder.encode(submissionId, StandardCharsets.UTF_8) + "/status";
        Map<String, Object> data = http.get(path);
        return new BatchStatus(
            Json.str(data, "submission_id") != null ? Json.str(data, "submission_id") : submissionId,
            Json.intVal(data, "total"),
            Json.intVal(data, "anchored"),
            Json.intVal(data, "pending")
        );
    }

    /**
     * Return all anchored inclusion proofs for a batch submission.
     *
     * @param submissionId the ID returned by {@link #anchorBatch}
     */
    public List<AnchorProof> getBatchProofs(String submissionId) {
        String path = "/anchor/batch/" + URLEncoder.encode(submissionId, StandardCharsets.UTF_8) + "/proofs";
        Map<String, Object> data = http.get(path);
        List<AnchorProof> proofs = new ArrayList<>();
        for (Map<String, Object> p : Json.array(data, "proofs")) {
            proofs.add(ApiClient.parseProof(p));
        }
        return proofs;
    }

    /**
     * Poll until all hashes in a batch submission are anchored, then return all proofs.
     * Polls with defaults: 900s timeout, 15s interval.
     */
    public List<AnchorProof> anchorBatchWait(BatchSubmission submission) {
        return anchorBatchWait(submission, 900, 15);
    }

    /**
     * Poll until all hashes in a batch submission are anchored, then return all proofs.
     *
     * @param submission  the {@link BatchSubmission} returned by {@link #anchorBatch}
     * @param timeoutSecs maximum seconds to wait
     * @param pollSecs    polling interval in seconds
     */
    public List<AnchorProof> anchorBatchWait(BatchSubmission submission, int timeoutSecs, int pollSecs) {
        long deadline = System.currentTimeMillis() + (long) timeoutSecs * 1000;
        while (true) {
            BatchStatus status = getBatchStatus(submission.getSubmissionId());
            if (status.getPending() == 0 && status.getTotal() > 0) {
                return getBatchProofs(submission.getSubmissionId());
            }
            if (System.currentTimeMillis() >= deadline) {
                throw new TrustBeatException(
                    "anchorBatchWait timed out after " + timeoutSecs + "s for " + submission.getSubmissionId());
            }
            try {
                Thread.sleep((long) pollSecs * 1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new TrustBeatException("anchorBatchWait interrupted");
            }
        }
    }

    /**
     * Retrieve a proof by tracking ID.
     * Returns {@code null} if the anchor is still pending.
     */
    public AnchorProof getProof(String trackingId) {
        String path = "/anchor/" + URLEncoder.encode(trackingId, StandardCharsets.UTF_8) + "/proof";
        Map<String, Object> data = http.get(path);
        if (!ApiClient.looksLikeProof(data)) return null;
        return ApiClient.parseProof(data);
    }

    /**
     * Poll until the proof is ready, then return it.
     *
     * @param trackingId  the ID returned by {@link #anchor}
     * @param timeoutSecs maximum seconds to wait (default 660 = 11 minutes)
     * @param pollSecs    polling interval in seconds (default 15)
     * @throws TrustBeatException wrapping {@link InterruptedException} if interrupted
     */
    public AnchorProof anchorWait(String trackingId, int timeoutSecs, int pollSecs) {
        long deadline = System.currentTimeMillis() + (long) timeoutSecs * 1000;
        while (true) {
            AnchorProof proof = getProof(trackingId);
            if (proof != null) return proof;
            if (System.currentTimeMillis() >= deadline) {
                throw new TrustBeatException(
                    "anchorWait timed out after " + timeoutSecs + "s for " + trackingId);
            }
            try {
                Thread.sleep((long) pollSecs * 1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new TrustBeatException("anchorWait interrupted");
            }
        }
    }

    /** Polls with defaults: 660s timeout, 15s interval. */
    public AnchorProof anchorWait(String trackingId) {
        return anchorWait(trackingId, 660, 15);
    }

    /**
     * Verify a Merkle inclusion proof locally — no network call.
     *
     * @return true if the proof is cryptographically valid
     * @throws VerificationException if the proof data is malformed
     */
    public boolean verify(AnchorProof proof) {
        return MerkleVerifier.verify(proof);
    }

    // ── File helpers ──────────────────────────────────────────────────────────

    /**
     * Hash a local file with SHA-256 and submit it for anchoring.
     *
     * <p>The file is read in 64 KB chunks and hashed locally — it is
     * <em>never uploaded</em>. Only the 64-character hex digest is sent to
     * the TrustBeat API. {@code description} is set to the filename.</p>
     *
     * @param path path to the file to anchor
     */
    public AnchorJob anchorFile(Path path) {
        return anchorFile(path, new AnchorOptions());
    }

    public AnchorJob anchorFile(Path path, AnchorOptions options) {
        String hash = hashFile(path);
        if (options.getDescription() == null) {
            options = new AnchorOptions()
                .clientRef(options.getClientRef())
                .description(path.getFileName().toString());
        }
        return anchor(hash, options);
    }

    /**
     * Hash a file, submit for anchoring, and block until the proof is ready.
     * Polls with defaults: 660s timeout, 15s interval.
     */
    public AnchorProof anchorFileWait(Path path) {
        return anchorFileWait(path, new AnchorOptions(), 660, 15);
    }

    public AnchorProof anchorFileWait(Path path, AnchorOptions options,
                                      int timeoutSecs, int pollSecs) {
        AnchorJob job = anchorFile(path, options);
        return anchorWait(job.getId(), timeoutSecs, pollSecs);
    }

    // ── Static hashing utilities ───────────────────────────────────────────────

    /**
     * SHA-256 hash of a local file, returned as a lowercase hex string.
     * Reads the file in 64 KB chunks — suitable for large files.
     */
    public static String hashFile(Path path) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            try (InputStream in = Files.newInputStream(path)) {
                int n;
                while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        } catch (IOException e) {
            throw new TrustBeatException("Failed to read file: " + path + " — " + e.getMessage());
        }
    }

    /**
     * SHA-256 hash of a byte array, returned as a lowercase hex string.
     * Convenience method for computing the hash before calling {@link #anchor}.
     */
    public static String hashBytes(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * SHA-256 hash of a UTF-8 string, returned as a lowercase hex string.
     */
    public static String hashString(String text) {
        return hashBytes(text.getBytes(StandardCharsets.UTF_8));
    }

    // ── AI Act Audit Anchoring ─────────────────────────────────────────────────

    /**
     * Submit an AI decision for EU AI Act Article 12 anchoring.
     *
     * <p>Privacy-safe: only hashes are sent — raw model inputs and outputs are
     * never uploaded.  Returns immediately with a tracking ID.
     * Use {@link #anchorAiDecisionWait(String)} to block until the proof is ready.
     *
     * @param inputHash  SHA-256 hex digest of the model input (64 lowercase hex chars)
     * @param outputHash SHA-256 hex digest of the model output/decision (64 hex chars)
     * @param metadata   decision metadata (model ID, risk category, oversight flag, etc.)
     */
    public AiDecisionJob anchorAiDecision(String inputHash, String outputHash,
                                          AiDecisionMetadata metadata) {
        String teJson = Json.buildObject(
            "started_at",   metadata.getTimeEnvelope().getStartedAt(),
            "completed_at", metadata.getTimeEnvelope().getCompletedAt()
        );
        String metaJson = Json.buildObject(
            "model_id",             metadata.getModelId(),
            "model_version",        metadata.getModelVersion(),
            "system_name",          metadata.getSystemName(),
            "risk_category",        metadata.getRiskCategory(),
            "decision_type",        metadata.getDecisionType(),
            "human_oversight",      String.valueOf(metadata.isHumanOversight()),
            "operator_id",          metadata.getOperatorId(),
            "deployment_env",       metadata.getDeploymentEnv(),
            "external_ref",         metadata.getExternalRef(),
            "decision_outcome",     metadata.getDecisionOutcome(),
            "model_artifact_hash",  metadata.getModelArtifactHash(),
            "data_subject_category", metadata.getDataSubjectCategory()
        );
        // Inject time_envelope object and fix human_oversight boolean
        metaJson = metaJson
            .replace("\"time_envelope\":\"null\"", "")  // remove placeholder
            .replace("\"human_oversight\":\"" + metadata.isHumanOversight() + "\"",
                     "\"human_oversight\":" + metadata.isHumanOversight());
        // Append time_envelope before closing brace
        metaJson = metaJson.substring(0, metaJson.lastIndexOf('}'))
            + (metaJson.lastIndexOf('{') == metaJson.lastIndexOf('}') - 1 ? "" : ",")
            + "\"time_envelope\":" + teJson + "}";

        String body = "{\"input_hash\":\"" + inputHash + "\","
            + "\"output_hash\":\"" + outputHash + "\","
            + "\"metadata\":" + metaJson + "}";

        Map<String, Object> data = http.post("/ai/decisions/anchor", body);
        return ApiClient.parseAiDecisionJob(data);
    }

    /**
     * Fetch the verification result for a previously submitted AI decision.
     * Returns {@code null} if the decision is still pending (not yet anchored).
     *
     * @param trackingId the ID returned by {@link #anchorAiDecision}
     */
    public AiDecisionProof getAiDecisionProof(String trackingId) {
        try {
            String path = "/ai/decisions/verify/" + URLEncoder.encode(trackingId, StandardCharsets.UTF_8);
            Map<String, Object> data = http.get(path);
            // Before anchoring the API returns 200 with verification_status
            // "PENDING" and no proof — treat that as "not ready yet" (null) so
            // pollers keep waiting.
            if ("PENDING".equals(data.get("verification_status"))) return null;
            return ApiClient.parseAiDecisionProof(data);
        } catch (NotFoundException e) {
            if ("NOT_ANCHORED".equals(e.getCode())) return null;
            throw e;
        }
    }

    /**
     * Poll until the AI decision proof is ready, then return it.
     * Polls with defaults: 660s timeout, 15s interval.
     */
    public AiDecisionProof anchorAiDecisionWait(String trackingId) {
        return anchorAiDecisionWait(trackingId, 660, 15);
    }

    public AiDecisionProof anchorAiDecisionWait(String trackingId, int timeoutSecs, int pollSecs) {
        long deadline = System.currentTimeMillis() + (long) timeoutSecs * 1000;
        while (true) {
            AiDecisionProof proof = getAiDecisionProof(trackingId);
            if (proof != null) return proof;
            if (System.currentTimeMillis() >= deadline) {
                throw new TrustBeatException(
                    "anchorAiDecisionWait timed out after " + timeoutSecs + "s for " + trackingId);
            }
            try {
                Thread.sleep((long) pollSecs * 1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new TrustBeatException("anchorAiDecisionWait interrupted");
            }
        }
    }

    // ── Signature & certificate verification ─────────────────────────────────

    /**
     * Verify eIDAS electronic signatures on a document.
     * <p>
     * Validates PAdES (PDF), CAdES (CMS), or XAdES (XML) signatures against the EU Trusted List.
     * Returns a full report with per-signature details and a top-level verdict.
     *
     * @param document document bytes (PDF, CMS/p7s, or XML)
     * @param format   "pades", "cades", or "xades"
     */
    public VerificationReport verifySignature(byte[] document, String format) {
        String b64 = Base64.getEncoder().encodeToString(document);
        String body = "{\"document_base64\":\"" + b64 + "\",\"format\":\"" + format + "\"}";
        Map<String, Object> data = http.post("/verify/signature", body);
        return ApiClient.parseVerificationReport(data);
    }

    /**
     * Verify eIDAS signatures and anchor the verification event.
     * <p>
     * Returns immediately (202 Accepted) with a tracking ID. Use
     * {@link #getVerification(String)} to retrieve the report.
     *
     * @param document document bytes
     * @param format   "pades", "cades", or "xades"
     */
    public VerificationJob verifyAndAnchor(byte[] document, String format) {
        String b64 = Base64.getEncoder().encodeToString(document);
        String body = "{\"document_base64\":\"" + b64 + "\",\"format\":\"" + format + "\",\"anchor\":true}";
        Map<String, Object> data = http.post("/verify/signature/anchored", body);
        return ApiClient.parseVerificationJob(data);
    }

    /**
     * Retrieve a saved verification report by tracking ID.
     *
     * @param trackingId ID returned by {@link #verifySignature} or {@link #verifyAndAnchor}
     * @throws NotFoundException if the tracking ID is unknown
     */
    public VerificationReport getVerification(String trackingId) {
        String path = "/verify/" + URLEncoder.encode(trackingId, StandardCharsets.UTF_8);
        Map<String, Object> data = http.get(path);
        return ApiClient.parseVerificationReport(data);
    }

    /**
     * Validate a standalone X.509 certificate (DER or PEM) against the EU Trusted List.
     * <p>
     * Checks certificate chain, revocation status (OCSP/CRL), qualified certificate
     * status, and QSCD flag.
     *
     * @param certificate DER- or PEM-encoded X.509 certificate bytes
     */
    public CertificateValidationResult validateCertificate(byte[] certificate) {
        String b64 = Base64.getEncoder().encodeToString(certificate);
        String body = "{\"certificate_base64\":\"" + b64 + "\"}";
        Map<String, Object> data = http.post("/validate/certificate", body);
        return ApiClient.parseCertValidationResult(data);
    }

    // ── Audit Trail ────────────────────────────────────────────────────────────

    /**
     * Submit a single audit event for tamper-evident Merkle anchoring.
     * Returns the {@code eventId} immediately (202 Accepted).
     *
     * @param trailCategory logical trail, e.g. {@code "financial"}
     * @param actor         who performed the action, e.g. {@code "user:42"}
     * @param action        machine-readable verb, e.g. {@code "payment.approved"}
     * @param ts            ISO 8601 timestamp of when the event occurred
     * @return event_id string
     */
    public String submitAuditEvent(String trailCategory, String actor, String action, String ts) {
        String body = Json.buildObject(
            "trail_category", trailCategory,
            "actor",          actor,
            "action",         action,
            "ts",             ts
        );
        Map<String, Object> data = http.post("/audit/events", body);
        return (String) data.get("event_id");
    }

    /**
     * Submit up to 1,000 audit events in a single batch request. Each event map uses
     * the same keys as {@link #submitAuditEvent} (trail_category, actor, action, ts).
     * Returns the event IDs in submission order.
     */
    @SuppressWarnings("unchecked")
    public List<String> submitAuditEvents(List<Map<String, Object>> events) {
        StringBuilder arr = new StringBuilder("[");
        for (int i = 0; i < events.size(); i++) {
            if (i > 0) arr.append(",");
            Map<String, Object> e = events.get(i);
            Object[] pairs = new Object[e.size() * 2];
            int j = 0;
            for (Map.Entry<String, Object> en : e.entrySet()) {
                pairs[j++] = en.getKey();
                pairs[j++] = en.getValue();
            }
            arr.append(Json.buildObject(pairs));
        }
        arr.append("]");
        Map<String, Object> data = http.post("/audit/events/batch", arr.toString());
        List<Object> ids = (List<Object>) data.getOrDefault("event_ids", List.of());
        List<String> out = new java.util.ArrayList<>();
        for (Object id : ids) out.add(id == null ? null : id.toString());
        return out;
    }

    /**
     * Fetch the Merkle inclusion proof for an anchored audit event.
     * Returns {@code null} if the event exists but is not yet anchored.
     *
     * @param eventId ID returned by {@link #submitAuditEvent}
     * @throws NotFoundException if the eventId is unknown
     */
    public AuditEventProof getAuditEventProof(String eventId) {
        Map<String, Object> data = http.get("/audit/events/" + eventId + "/proof");
        String status = (String) data.get("status");
        if ("pending".equals(status)) return null;
        return ApiClient.parseAuditEventProof(data);
    }

    /**
     * Query audit events with optional filters. Returns one page of results.
     *
     * @param trailCategory filter by trail category (null = any)
     * @param page          1-based page number
     * @param pageSize      events per page (max 100)
     */
    @SuppressWarnings("unchecked")
    public List<AuditEvent> listAuditEvents(String trailCategory, int page, int pageSize) {
        StringBuilder qs = new StringBuilder("/audit/events?page=")
            .append(page).append("&page_size=").append(pageSize);
        if (trailCategory != null && !trailCategory.isEmpty())
            qs.append("&trail_category=").append(trailCategory);
        Map<String, Object> data = http.get(qs.toString());
        List<Map<String, Object>> events = (List<Map<String, Object>>) data.getOrDefault("events", List.of());
        return events.stream().map(ApiClient::parseAuditEvent).collect(java.util.stream.Collectors.toList());
    }

    /**
     * Export audit events as a court-admissible ZIP package.
     * Blocks until the export job completes (polls every 3 s, up to 5 min).
     *
     * @param trailCategory restrict to one trail category, or null for all
     * @param fromIso       ISO 8601 start timestamp (required)
     * @param toIso         ISO 8601 end timestamp (required)
     * @return ZIP file bytes
     * @throws IllegalArgumentException if fromIso or toIso is null/blank
     */
    public byte[] exportAuditEvents(String trailCategory, String fromIso, String toIso) {
        if (fromIso == null || fromIso.isBlank() || toIso == null || toIso.isBlank())
            throw new IllegalArgumentException("exportAuditEvents requires both fromIso and toIso");
        StringBuilder body = new StringBuilder("{");
        body.append("\"from\":\"").append(fromIso).append("\",");
        body.append("\"to\":\"").append(toIso).append("\"");
        if (trailCategory != null) body.append(",\"trail_category\":\"").append(trailCategory).append("\"");
        body.append("}");
        Map<String, Object> jobData = http.post("/audit/export", body.toString());
        String jobId = (String) jobData.get("job_id");
        long deadline = System.currentTimeMillis() + 300_000L;
        while (true) {
            ApiClient.RawResponse raw = http.getRaw("/audit/export/" + jobId);
            if (raw.isZip()) return raw.body;
            Map<String, Object> status = raw.json();
            String s = (String) status.get("status");
            if ("failed".equals(s)) throw new TrustBeatException((String) status.getOrDefault("error", "Export failed"), 0, null);
            if (System.currentTimeMillis() > deadline) throw new TrustBeatException("Export timed out", 0, null);
            try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
        throw new TrustBeatException("Export interrupted", 0, null);
    }

    // ── Tamper-Evident Logs (NIS2) ──────────────────────────────────────────────

    /** Submit a log hash for NIS2 Article 21 anchoring (no label). */
    public LogAnchorJob anchorLog(String logHash, LogMetadata metadata) {
        return anchorLog(logHash, metadata, null);
    }

    /**
     * Submit a log hash for NIS2 Article 21 tamper-evident anchoring. Returns
     * immediately (202); the log is anchored in the next batch (~10 min). The server
     * binds {@code metadata} into the Merkle leaf.
     *
     * @param logHash  SHA-256 hex digest of the log content (64 hex chars)
     * @param metadata log source and identity context
     * @param label    optional free-text cross-reference label, or null
     */
    public LogAnchorJob anchorLog(String logHash, LogMetadata metadata, String label) {
        String outer = Json.buildObject("log_hash", logHash, "label", label);
        String body = outer.substring(0, outer.lastIndexOf('}'))
            + ",\"metadata\":" + logMetadataJson(metadata) + "}";
        Map<String, Object> data = http.post("/logs/anchor", body);
        return ApiClient.parseLogAnchorJob(data);
    }

    /**
     * Fetch the verification result for a log anchor. Returns {@code null} while the
     * log is still pending (verification_status "PENDING"). Throws
     * {@link NotFoundException} if the tracking ID is unknown.
     */
    public LogProof getLogProof(String trackingId) {
        String path = "/logs/verify/" + URLEncoder.encode(trackingId, StandardCharsets.UTF_8);
        Map<String, Object> data = http.get(path);
        if ("PENDING".equals(data.get("verification_status"))) return null;
        return ApiClient.parseLogProof(data);
    }

    /** Get the lightweight status of a log anchor submission (cheap polling). */
    public LogStatus getLogStatus(String trackingId) {
        String path = "/logs/" + URLEncoder.encode(trackingId, StandardCharsets.UTF_8) + "/status";
        return ApiClient.parseLogStatus(http.get(path));
    }

    /**
     * List recent log anchor submissions. Any of {@code status} ("pending"/"anchored"),
     * {@code fromIso}, {@code toIso} may be null to omit that filter.
     */
    @SuppressWarnings("unchecked")
    public List<LogAnchorListItem> listLogs(String status, String fromIso, String toIso) {
        java.util.List<String> parts = new java.util.ArrayList<>();
        if (status  != null && !status.isEmpty())  parts.add("status=" + status);
        if (fromIso != null && !fromIso.isEmpty()) parts.add("from=" + fromIso);
        if (toIso   != null && !toIso.isEmpty())   parts.add("to=" + toIso);
        String path = "/logs" + (parts.isEmpty() ? "" : "?" + String.join("&", parts));
        Map<String, Object> data = http.get(path);
        List<Map<String, Object>> logs = (List<Map<String, Object>>) data.getOrDefault("logs", List.of());
        return logs.stream().map(ApiClient::parseLogAnchorListItem).collect(java.util.stream.Collectors.toList());
    }

    /**
     * Download a portable NIS2 log proof bundle (bundle_type "trustbeat.log.proof").
     * Returns the raw JSON bundle bytes. Throws {@link NotFoundException} if unknown/not anchored.
     */
    public byte[] exportLog(String trackingId) {
        String path = "/logs/" + URLEncoder.encode(trackingId, StandardCharsets.UTF_8) + "/export";
        ApiClient.RawResponse raw = http.getRaw(path);
        if (raw.status == 404) throw new NotFoundException("Log " + trackingId + " not found", "NOT_FOUND");
        if (raw.status < 200 || raw.status >= 300)
            throw new TrustBeatException("Log export failed: HTTP " + raw.status, raw.status, null);
        return raw.body;
    }

    /** Poll getLogProof() until the log is anchored, then return the proof (660s/15s defaults). */
    public LogProof anchorLogWait(String trackingId) {
        return anchorLogWait(trackingId, 660, 15);
    }

    public LogProof anchorLogWait(String trackingId, int timeoutSecs, int pollSecs) {
        long deadline = System.currentTimeMillis() + (long) timeoutSecs * 1000;
        while (true) {
            LogProof proof = getLogProof(trackingId);
            if (proof != null) return proof;
            if (System.currentTimeMillis() > deadline)
                throw new TrustBeatException("anchorLogWait timed out for " + trackingId, 0, null);
            try { Thread.sleep((long) pollSecs * 1000); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
        throw new TrustBeatException("anchorLogWait interrupted", 0, null);
    }

    private static String logMetadataJson(LogMetadata m) {
        LogSource s = m.getLogSource();
        String src = Json.buildObject("uri", s.getUri(), "name", s.getName(), "size_bytes", s.getSizeBytes());
        LogSourceIdentity id = m.getSourceIdentity();
        String ident = Json.buildObject(
            "system_uuid",       id.getSystemUuid(),
            "cloud_instance_id", id.getCloudInstanceId(),
            "hostname",          id.getHostname(),
            "service_name",      id.getServiceName(),
            "tenant_id",         id.getTenantId());
        StringBuilder sb = new StringBuilder("{\"log_source\":").append(src)
            .append(",\"source_identity\":").append(ident);
        if (m.getTimeEnvelope() != null) {
            sb.append(",\"time_envelope\":").append(Json.buildObject(
                "start_at", m.getTimeEnvelope().getStartAt(),
                "end_at",   m.getTimeEnvelope().getEndAt()));
        }
        return sb.append("}").toString();
    }
}
