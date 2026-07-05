package eu.trustbeat.sdk.internal;

import eu.trustbeat.sdk.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Low-level HTTP client wrapping java.net.http.HttpClient.
 * Handles auth, JSON serialisation/deserialisation, and error mapping.
 */
public final class ApiClient {

    private final String     apiKey;
    private final String     baseUrl;
    private final HttpClient http;

    public ApiClient(String apiKey, String baseUrl, Duration timeout) {
        this.apiKey  = apiKey;
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.http    = HttpClient.newBuilder()
                                 .connectTimeout(timeout)
                                 .build();
    }

    // ── Low-level HTTP ─────────────────────────────────────────────────────────

    public Map<String, Object> post(String path, String jsonBody) {
        return send("POST", path, jsonBody);
    }

    public Map<String, Object> get(String path) {
        return send("GET", path, null);
    }

    /** A raw HTTP response for endpoints that may return binary data. */
    public static final class RawResponse {
        public final int    status;
        public final String contentType;
        public final byte[] body;
        public RawResponse(int status, String contentType, byte[] body) {
            this.status = status; this.contentType = contentType; this.body = body;
        }
        public boolean isZip() { return contentType != null && contentType.startsWith("application/zip"); }
        public Map<String, Object> json() { return Json.parseObject(new String(body, StandardCharsets.UTF_8)); }
    }

    public RawResponse getRaw(String path) {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .header("Authorization", "Bearer " + apiKey)
            .timeout(Duration.ofSeconds(60))
            .GET()
            .build();
        HttpResponse<byte[]> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TrustBeatException("Request failed: " + e.getMessage());
        }
        String ct = resp.headers().firstValue("content-type").orElse("");
        return new RawResponse(resp.statusCode(), ct, resp.body());
    }

    private Map<String, Object> send(String method, String path, String body) {
        HttpRequest.Builder req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .header("Authorization", "Bearer " + apiKey)
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(30));

        if (body != null) {
            req.header("Content-Type", "application/json");
            req.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        } else {
            req.method(method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<String> resp;
        try {
            resp = http.send(req.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TrustBeatException("Request failed: " + e.getMessage());
        }

        String responseBody = resp.body();
        Map<String, Object> data;
        try {
            data = Json.parseObject(responseBody);
        } catch (Exception e) {
            data = Map.of("error", Map.of("message", responseBody));
        }

        int status = resp.statusCode();
        if (status < 200 || status >= 300) {
            String msg  = extractErrorMessage(data, status);
            String code = extractErrorCode(data);
            switch (status) {
                case 401: throw new AuthException(msg);
                case 402: throw new QuotaException(msg);
                case 404: throw new NotFoundException(msg, code != null ? code : "NOT_FOUND");
                case 429: throw new RateLimitException(msg);
                default:  throw new TrustBeatException(msg, status, code);
            }
        }

        return data;
    }

    @SuppressWarnings("unchecked")
    private String extractErrorMessage(Map<String, Object> data, int status) {
        Object err = data.get("error");
        if (err instanceof Map) {
            Object msg = ((Map<String, Object>) err).get("message");
            if (msg != null) return msg.toString();
        }
        return "HTTP " + status;
    }

    @SuppressWarnings("unchecked")
    private String extractErrorCode(Map<String, Object> data) {
        Object err = data.get("error");
        if (err instanceof Map) {
            Object code = ((Map<String, Object>) err).get("code");
            if (code != null) return code.toString();
        }
        return null;
    }

    // ── Response parsers ───────────────────────────────────────────────────────

    public static AnchorJob parseAnchorJob(Map<String, Object> d) {
        return new AnchorJob(
            Json.str(d, "id"),
            Json.str(d, "hash"),
            Json.str(d, "hash_algorithm"),
            Json.str(d, "status"),
            Json.str(d, "submitted_at"),
            Json.bool(d, "overage", false)
        );
    }

    public static AnchorProof parseProof(Map<String, Object> d) {
        List<ProofStep> path = Json.array(d, "proof_path").stream()
            .map(s -> new ProofStep(Json.str(s, "sibling"), Json.str(s, "side")))
            .collect(Collectors.toList());

        String tokenB64 = Json.str(d, "token");
        byte[] token = tokenB64 != null
            ? Base64.getDecoder().decode(tokenB64)
            : new byte[0];

        return new AnchorProof(
            Json.str(d, "id"),
            Json.str(d, "hash"),
            Json.str(d, "hash_algorithm"),
            Json.str(d, "batch_id"),
            Json.intVal(d, "leaf_index"),
            Json.str(d, "merkle_root"),
            path,
            token,
            Json.str(d, "token_format"),
            Json.str(d, "tsa_serial"),
            Json.str(d, "provider"),
            Json.str(d, "anchored_at"),
            Json.str(d, "client_ref"),
            Json.str(d, "description")
        );
    }

    /** Returns true if the response looks like a completed proof (has merkle_root). */
    public static boolean looksLikeProof(Map<String, Object> data) {
        return data.containsKey("merkle_root") && data.get("merkle_root") != null;
    }

    @SuppressWarnings("unchecked")
    public static AiDecisionJob parseAiDecisionJob(Map<String, Object> d) {
        return new AiDecisionJob(
            Json.str(d, "id"),
            Json.str(d, "input_hash"),
            Json.str(d, "output_hash"),
            Json.str(d, "combined_hash"),
            Json.str(d, "status"),
            Json.str(d, "submitted_at"),
            Json.bool(d, "overage", false)
        );
    }

    @SuppressWarnings("unchecked")
    public static AiDecisionProof parseAiDecisionProof(Map<String, Object> d) {
        Map<String, Object> m = (Map<String, Object>) d.get("metadata");
        Map<String, Object> te = (Map<String, Object>) m.get("time_envelope");
        AiDecisionMetadata meta = new AiDecisionMetadata.Builder()
            .modelId(Json.str(m, "model_id"))
            .modelVersion(Json.str(m, "model_version"))
            .systemName(Json.str(m, "system_name"))
            .riskCategory(Json.str(m, "risk_category"))
            .decisionType(Json.str(m, "decision_type"))
            .humanOversight(Json.bool(m, "human_oversight", false))
            .timeEnvelope(new AiTimeEnvelope(Json.str(te, "started_at"), Json.str(te, "completed_at")))
            .operatorId(Json.str(m, "operator_id"))
            .deploymentEnv(Json.str(m, "deployment_env"))
            .externalRef(Json.str(m, "external_ref"))
            .decisionOutcome(Json.str(m, "decision_outcome"))
            .modelArtifactHash(Json.str(m, "model_artifact_hash"))
            .dataSubjectCategory(Json.str(m, "data_subject_category"))
            .build();

        AnchorProof proof = null;
        Object proofObj = d.get("proof");
        if (proofObj instanceof Map) {
            proof = parseProof((Map<String, Object>) proofObj);
        }

        return new AiDecisionProof(
            Json.str(d, "id"),
            Json.str(d, "input_hash"),
            Json.str(d, "output_hash"),
            Json.str(d, "combined_hash"),
            meta,
            Json.str(d, "verification_status"),
            Json.str(d, "anchored_at"),
            proof
        );
    }

    @SuppressWarnings("unchecked")
    private static eu.trustbeat.sdk.SignatureDetail parseSignatureDetail(Map<String, Object> d) {
        return new eu.trustbeat.sdk.SignatureDetail(
            Json.intVal(d, "index"),
            Json.str(d, "signer_name"),
            Json.str(d, "signer_email"),
            Json.str(d, "signing_time"),
            Json.str(d, "cert_serial"),
            Json.str(d, "cert_fingerprint"),
            Json.str(d, "cert_issuer"),
            Json.bool(d, "qualified", false),
            Json.bool(d, "on_eutl", false),
            Json.bool(d, "qscd", false),
            Json.str(d, "revocation_status"),
            Json.str(d, "revocation_time"),
            Json.str(d, "ocsp_response"),
            Json.str(d, "signature_level"),
            Json.bool(d, "timestamp_present", false),
            Json.str(d, "timestamp_serial"),
            Json.str(d, "verdict")
        );
    }

    @SuppressWarnings("unchecked")
    public static eu.trustbeat.sdk.VerificationReport parseVerificationReport(Map<String, Object> d) {
        List<Map<String, Object>> sigs = (List<Map<String, Object>>) d.getOrDefault("signatures", List.of());
        List<eu.trustbeat.sdk.SignatureDetail> details = sigs.stream()
            .map(ApiClient::parseSignatureDetail)
            .collect(Collectors.toList());
        return new eu.trustbeat.sdk.VerificationReport(
            Json.str(d, "verdict"),
            details,
            Json.str(d, "document_hash"),
            Json.str(d, "checked_at"),
            Json.str(d, "eutl_version"),
            Json.str(d, "tracking_id")
        );
    }

    public static eu.trustbeat.sdk.VerificationJob parseVerificationJob(Map<String, Object> d) {
        return new eu.trustbeat.sdk.VerificationJob(
            Json.str(d, "tracking_id"),
            Json.str(d, "document_hash"),
            Json.str(d, "status"),
            Json.str(d, "submitted_at")
        );
    }

    @SuppressWarnings("unchecked")
    public static eu.trustbeat.sdk.AuditEvent parseAuditEvent(Map<String, Object> d) {
        return new eu.trustbeat.sdk.AuditEvent(
            Json.str(d, "event_id"),
            Json.str(d, "trail_category"),
            Json.str(d, "actor"),
            Json.str(d, "action"),
            Json.str(d, "ts"),
            Json.str(d, "received_at"),
            Json.bool(d, "anchored", false),
            Json.str(d, "system"),
            Json.str(d, "resource")
        );
    }

    @SuppressWarnings("unchecked")
    public static eu.trustbeat.sdk.AuditEventProof parseAuditEventProof(Map<String, Object> d) {
        List<Map<String, Object>> rawPath = (List<Map<String, Object>>) d.getOrDefault("merkle_path", List.of());
        List<eu.trustbeat.sdk.AuditProofStep> path = rawPath.stream()
            .map(s -> new eu.trustbeat.sdk.AuditProofStep(Json.str(s, "sibling"), Json.str(s, "side")))
            .collect(Collectors.toList());
        return new eu.trustbeat.sdk.AuditEventProof(
            Json.str(d, "event_id"),
            Json.str(d, "canonical_hash"),
            Json.str(d, "batch_id"),
            Json.intVal(d, "leaf_index"),
            path,
            Json.str(d, "anchored_at")
        );
    }

    public static eu.trustbeat.sdk.AuditExportJob parseAuditExportJob(Map<String, Object> d) {
        Object ec = d.get("event_count");
        Integer eventCount = (ec instanceof Number) ? ((Number) ec).intValue() : null;
        return new eu.trustbeat.sdk.AuditExportJob(
            Json.str(d, "job_id"),
            Json.str(d, "status"),
            eventCount,
            Json.str(d, "error")
        );
    }

    public static eu.trustbeat.sdk.CertificateValidationResult parseCertValidationResult(Map<String, Object> d) {
        List<String> keyUsage = (List<String>) d.getOrDefault("key_usage", List.of());
        return new eu.trustbeat.sdk.CertificateValidationResult(
            Json.str(d, "subject"),
            Json.str(d, "issuer"),
            Json.str(d, "serial"),
            Json.str(d, "not_before"),
            Json.str(d, "not_after"),
            Json.bool(d, "qualified", false),
            Json.bool(d, "on_eutl", false),
            Json.bool(d, "qscd", false),
            Json.str(d, "revocation_status"),
            Json.str(d, "revocation_time"),
            keyUsage,
            Json.bool(d, "valid", false),
            Json.str(d, "validated_at")
        );
    }

    // ── Tamper-Evident Logs (NIS2) ──────────────────────────────────────────────

    public static eu.trustbeat.sdk.LogAnchorJob parseLogAnchorJob(Map<String, Object> d) {
        return new eu.trustbeat.sdk.LogAnchorJob(
            Json.str(d, "id"),
            Json.str(d, "log_hash"),
            Json.str(d, "combined_hash"),
            Json.str(d, "status"),
            Json.str(d, "submitted_at"),
            Json.bool(d, "overage", false),
            Json.str(d, "label")
        );
    }

    public static eu.trustbeat.sdk.LogStatus parseLogStatus(Map<String, Object> d) {
        return new eu.trustbeat.sdk.LogStatus(
            Json.str(d, "id"),
            Json.str(d, "status"),
            Json.str(d, "submitted_at"),
            Json.str(d, "anchored_at")
        );
    }

    public static eu.trustbeat.sdk.LogAnchorListItem parseLogAnchorListItem(Map<String, Object> d) {
        return new eu.trustbeat.sdk.LogAnchorListItem(
            Json.str(d, "id"),
            Json.str(d, "log_hash"),
            Json.str(d, "status"),
            Json.str(d, "submitted_at"),
            Json.str(d, "log_source_uri"),
            Json.str(d, "anchored_at"),
            Json.str(d, "service_name"),
            Json.str(d, "label")
        );
    }

    @SuppressWarnings("unchecked")
    public static eu.trustbeat.sdk.LogProof parseLogProof(Map<String, Object> d) {
        eu.trustbeat.sdk.LogMetadata meta = parseLogMetadata((Map<String, Object>) d.get("metadata"));

        AnchorProof proof = null;
        Object proofObj = d.get("proof");
        if (proofObj instanceof Map) proof = parseProof((Map<String, Object>) proofObj);

        java.util.List<String> failures = null;
        Object fr = d.get("failure_reasons");
        if (fr instanceof java.util.List) {
            failures = new java.util.ArrayList<>();
            for (Object o : (java.util.List<?>) fr) failures.add(o == null ? null : o.toString());
        }

        return new eu.trustbeat.sdk.LogProof(
            Json.str(d, "id"),
            Json.str(d, "log_hash"),
            meta,
            Json.str(d, "combined_hash"),
            Json.str(d, "verification_status"),
            Json.intVal(d, "archive_stamps_count"),
            Json.str(d, "anchored_at"),
            proof,
            failures
        );
    }

    @SuppressWarnings("unchecked")
    private static eu.trustbeat.sdk.LogMetadata parseLogMetadata(Map<String, Object> m) {
        Map<String, Object> src   = (Map<String, Object>) m.get("log_source");
        Map<String, Object> ident = (Map<String, Object>) m.getOrDefault("source_identity", java.util.Map.of());
        Map<String, Object> te    = (Map<String, Object>) m.get("time_envelope");

        eu.trustbeat.sdk.LogSource.Builder sb = new eu.trustbeat.sdk.LogSource.Builder()
            .uri(Json.str(src, "uri"))
            .name(Json.str(src, "name"));
        if (src.get("size_bytes") != null) sb.sizeBytes(Json.intVal(src, "size_bytes"));

        eu.trustbeat.sdk.LogSourceIdentity identity = new eu.trustbeat.sdk.LogSourceIdentity.Builder()
            .systemUuid(Json.str(ident, "system_uuid"))
            .cloudInstanceId(Json.str(ident, "cloud_instance_id"))
            .hostname(Json.str(ident, "hostname"))
            .serviceName(Json.str(ident, "service_name"))
            .tenantId(Json.str(ident, "tenant_id"))
            .build();

        eu.trustbeat.sdk.LogMetadata.Builder mb = new eu.trustbeat.sdk.LogMetadata.Builder()
            .logSource(sb.build())
            .sourceIdentity(identity);
        if (te != null) mb.timeEnvelope(new eu.trustbeat.sdk.LogTimeEnvelope(Json.str(te, "start_at"), Json.str(te, "end_at")));
        return mb.build();
    }
}
