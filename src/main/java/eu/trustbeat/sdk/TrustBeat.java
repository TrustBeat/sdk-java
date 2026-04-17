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
            "hash_algorithm", "sha256",
            "client_ref",     options.getClientRef(),
            "description",    options.getDescription()
        );
        Map<String, Object> data = http.post("/anchors", body);
        return ApiClient.parseAnchorJob(data);
    }

    /**
     * Submit up to 100 SHA-256 hashes in a single batch request.
     * Returns an empty list immediately for empty input.
     */
    public List<AnchorJob> anchorBatch(List<String> hashes) {
        return anchorBatch(hashes, new AnchorOptions());
    }

    public List<AnchorJob> anchorBatch(List<String> hashes, AnchorOptions options) {
        if (hashes.isEmpty()) return new ArrayList<>();
        if (hashes.size() > 100)
            throw new IllegalArgumentException("anchorBatch: maximum 100 hashes per request");

        StringBuilder items = new StringBuilder("[");
        for (int i = 0; i < hashes.size(); i++) {
            if (i > 0) items.append(",");
            items.append(Json.buildObject("hash", hashes.get(i), "hash_algorithm", "sha256"));
        }
        items.append("]");

        String body = Json.buildObject(
            "hashes",      items.toString(),
            "client_ref",  options.getClientRef(),
            "description", options.getDescription()
        );

        // The hashes value is already a JSON array — strip the extra quotes
        body = body.replace("\"hashes\":\"" + items + "\"", "\"hashes\":" + items);

        Map<String, Object> data = http.post("/anchors/batch", body);
        List<AnchorJob> jobs = new ArrayList<>();
        for (Map<String, Object> item : Json.array(data, "accepted")) {
            jobs.add(ApiClient.parseAnchorJob(item));
        }
        return jobs;
    }

    /**
     * Retrieve a proof by tracking ID.
     * Returns {@code null} if the anchor is still pending.
     */
    public AnchorProof getProof(String trackingId) {
        String path = "/anchors/" + URLEncoder.encode(trackingId, StandardCharsets.UTF_8);
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

    /**
     * Request a direct (non-Merkle) qualified timestamp for a single hash.
     */
    public TimestampResult timestamp(String hash) {
        return timestamp(hash, new AnchorOptions());
    }

    public TimestampResult timestamp(String hash, AnchorOptions options) {
        String body = Json.buildObject(
            "hash",           hash,
            "hash_algorithm", "sha256",
            "client_ref",     options.getClientRef(),
            "description",    options.getDescription()
        );
        Map<String, Object> data = http.post("/timestamps", body);
        return ApiClient.parseTimestamp(data);
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
            "model_id",        metadata.getModelId(),
            "model_version",   metadata.getModelVersion(),
            "system_name",     metadata.getSystemName(),
            "risk_category",   metadata.getRiskCategory(),
            "decision_type",   metadata.getDecisionType(),
            "human_oversight", String.valueOf(metadata.isHumanOversight()),
            "operator_id",     metadata.getOperatorId(),
            "deployment_env",  metadata.getDeploymentEnv()
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
}
