package eu.trustbeat.sdk;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * TrustBeat Java SDK smoke CLI — drives the SDK against a LIVE API.
 *
 * Driven by tests/e2e/sdk_smoke.py (the orchestrator). Run via
 * {@code java -cp target/classes eu.trustbeat.sdk.Smoke <cmd> [id]}. Commands:
 *
 *   submit              anchor TB_HASH, print the tracking id
 *   verify &lt;id&gt;         fetch the proof via the SDK, check the contract, verify locally
 *   submit-batch        anchor a batch from TB_BATCH_SEED/TB_BATCH_N, print submission id
 *   verify-batch &lt;id&gt;   fetch batch proofs, check the contract, verify each locally
 *
 * Env: TB_BASE_URL (includes /v1), TB_API_KEY, TB_HASH, TB_BATCH_SEED, TB_BATCH_N
 * Exit 0 on success, non-zero on any failure.
 */
public final class Smoke {

    private static void fail(String msg) {
        System.err.println(msg);
        System.exit(1);
    }

    private static TrustBeat client() {
        return new TrustBeat.Builder()
            .apiKey(System.getenv("TB_API_KEY"))
            .baseUrl(System.getenv("TB_BASE_URL"))
            .build();
    }

    private static List<String> batchHashes() {
        String seed = System.getenv("TB_BATCH_SEED");
        int n = Integer.parseInt(System.getenv("TB_BATCH_N"));
        List<String> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(TrustBeat.hashString(seed + "::" + i));
        }
        return out;
    }

    // Fixed AI-decision metadata — only the input/output hashes vary per run.
    private static AiDecisionMetadata aiMeta() {
        return new AiDecisionMetadata.Builder()
            .modelId("claude-opus-4-8")
            .systemName("trustbeat-sdk-smoke")
            .riskCategory("employment")
            .decisionType("classification")
            .humanOversight(true)
            .timeEnvelope(new AiTimeEnvelope("2026-06-29T10:00:00Z", "2026-06-29T10:00:01Z"))
            .build();
    }

    private static String env(String name) {
        return System.getenv(name);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) fail("usage: Smoke {submit|verify <id>|submit-batch|verify-batch <id>"
            + "|submit-ai|verify-ai <id>|submit-file|submit-audit|verify-audit <id>|verify-sig|validate-cert}");
        String cmd = args[0];

        switch (cmd) {
            case "submit": {
                AnchorJob job = client().anchor(System.getenv("TB_HASH"));
                if (job.getId() == null || job.getId().isEmpty()) fail("submit: empty tracking id");
                System.out.println(job.getId());
                break;
            }
            case "verify": {
                if (args.length < 2) fail("usage: Smoke verify <id>");
                String id = args[1];
                String expected = System.getenv("TB_HASH");
                TrustBeat c = client();
                AnchorProof proof = c.getProof(id);
                if (proof == null) fail("verify: proof for " + id + " not ready");
                if (expected != null && !proof.getHash().equalsIgnoreCase(expected))
                    fail("verify: hash echo mismatch " + proof.getHash() + " != " + expected);
                if (proof.getMerkleRoot() == null || proof.getMerkleRoot().isEmpty())
                    fail("verify: empty merkle_root");
                if (proof.getToken() == null || proof.getToken().length == 0)
                    fail("verify: empty token");
                if (!c.verify(proof)) fail("verify: local Merkle verification failed");
                System.out.println("OK id=" + id + " root=" + proof.getMerkleRoot().substring(0, 16)
                    + "… token=" + proof.getToken().length + "B");
                break;
            }
            case "submit-batch": {
                List<String> hashes = batchHashes();
                BatchSubmission sub = client().anchorBatch(hashes);
                if (sub.getSubmissionId() == null || sub.getSubmissionId().isEmpty())
                    fail("submit-batch: empty submission_id");
                if (sub.getItems().size() != hashes.size())
                    fail("submit-batch: accepted " + sub.getItems().size() + " != " + hashes.size());
                System.out.println(sub.getSubmissionId());
                break;
            }
            case "verify-batch": {
                if (args.length < 2) fail("usage: Smoke verify-batch <id>");
                String sid = args[1];
                Set<String> expected = new HashSet<>();
                for (String h : batchHashes()) expected.add(h.toLowerCase());
                TrustBeat c = client();
                List<AnchorProof> proofs = c.getBatchProofs(sid);
                if (proofs.size() != expected.size())
                    fail("verify-batch: got " + proofs.size() + " proofs, want " + expected.size());
                for (AnchorProof p : proofs) {
                    if (!expected.contains(p.getHash().toLowerCase()))
                        fail("verify-batch: unexpected proof hash " + p.getHash());
                    if (p.getMerkleRoot() == null || p.getMerkleRoot().isEmpty()
                        || p.getToken() == null || p.getToken().length == 0)
                        fail("verify-batch: empty merkle_root/token for " + p.getId());
                    if (!c.verify(p)) fail("verify-batch: local Merkle verification failed for " + p.getId());
                }
                System.out.println("OK batch sid=" + sid + " n=" + proofs.size());
                break;
            }
            case "submit-ai": {
                AiDecisionJob job = client().anchorAiDecision(env("TB_AI_INPUT"), env("TB_AI_OUTPUT"), aiMeta());
                if (job.getId() == null || job.getId().isEmpty()) fail("submit-ai: empty tracking id");
                System.out.println(job.getId());
                break;
            }
            case "verify-ai": {
                if (args.length < 2) fail("usage: Smoke verify-ai <id>");
                String id = args[1];
                String inHash = env("TB_AI_INPUT"), outHash = env("TB_AI_OUTPUT");
                TrustBeat c = client();
                AiDecisionProof proof = c.getAiDecisionProof(id);
                if (proof == null) fail("verify-ai: proof for " + id + " not ready");
                if (!proof.getInputHash().equalsIgnoreCase(inHash))
                    fail("verify-ai: input_hash echo mismatch " + proof.getInputHash() + " != " + inHash);
                if (!proof.getOutputHash().equalsIgnoreCase(outHash))
                    fail("verify-ai: output_hash echo mismatch " + proof.getOutputHash() + " != " + outHash);
                if (!"VERIFIED".equals(proof.getVerificationStatus()))
                    fail("verify-ai: status " + proof.getVerificationStatus() + " != VERIFIED");
                if (proof.getProof() == null) fail("verify-ai: missing Merkle proof");
                if (!c.verify(proof.getProof())) fail("verify-ai: local Merkle verification failed");
                System.out.println("OK ai id=" + id + " combined="
                    + proof.getCombinedHash().substring(0, 16) + "…");
                break;
            }
            case "submit-file": {
                AnchorJob job = client().anchorFile(Path.of(env("TB_FILE_PATH")));
                if (job.getId() == null || job.getId().isEmpty()) fail("submit-file: empty tracking id");
                System.out.println(job.getId());
                break;
            }
            case "submit-audit": {
                String eventId = client().submitAuditEvent(
                    env("TB_AUDIT_CATEGORY"), env("TB_AUDIT_ACTOR"),
                    env("TB_AUDIT_ACTION"), env("TB_AUDIT_TS"));
                if (eventId == null || eventId.isEmpty()) fail("submit-audit: empty event_id");
                System.out.println(eventId);
                break;
            }
            case "verify-audit": {
                if (args.length < 2) fail("usage: Smoke verify-audit <id>");
                String id = args[1];
                TrustBeat c = client();
                AuditEventProof proof = c.getAuditEventProof(id);
                if (proof == null) fail("verify-audit: proof for " + id + " not ready");
                if (!proof.getEventId().equals(id))
                    fail("verify-audit: event_id echo mismatch " + proof.getEventId() + " != " + id);
                if (proof.getCanonicalHash() == null || proof.getCanonicalHash().isEmpty())
                    fail("verify-audit: empty canonical_hash");
                if (proof.getBatchId() == null || proof.getBatchId().isEmpty())
                    fail("verify-audit: empty batch_id");
                if (proof.getLeafIndex() < 0 || proof.getMerklePath() == null)
                    fail("verify-audit: invalid leaf_index/merkle_path");
                List<AuditEvent> events = c.listAuditEvents(env("TB_AUDIT_CATEGORY"), 1, 25);
                if (events.stream().noneMatch(e -> e.getEventId().equals(id)))
                    fail("verify-audit: " + id + " not returned by listAuditEvents");
                System.out.println("OK audit id=" + id + " batch="
                    + proof.getBatchId().substring(0, Math.min(12, proof.getBatchId().length()))
                    + "… leaf=" + proof.getLeafIndex());
                break;
            }
            case "verify-sig": {
                byte[] doc = Files.readAllBytes(Path.of(env("TB_SIG_DOC")));
                String expected = env("TB_SIG_DOCHASH");
                VerificationReport report = client().verifySignature(doc, env("TB_SIG_FORMAT"));
                if (!report.getDocumentHash().equalsIgnoreCase(expected))
                    fail("verify-sig: document_hash mismatch " + report.getDocumentHash() + " != " + expected);
                if (report.getVerdict() == null || report.getVerdict().isEmpty())
                    fail("verify-sig: empty verdict");
                if (report.getSignatures() == null || report.getSignatures().isEmpty())
                    fail("verify-sig: report has no signatures");
                System.out.println("OK sig verdict=" + report.getVerdict()
                    + " signatures=" + report.getSignatures().size());
                break;
            }
            case "validate-cert": {
                byte[] cert = Files.readAllBytes(Path.of(env("TB_CERT_PATH")));
                CertificateValidationResult res = client().validateCertificate(cert);
                if (res.getSubject() == null || res.getSubject().isEmpty())
                    fail("validate-cert: empty subject");
                if (res.getIssuer() == null || res.getIssuer().isEmpty())
                    fail("validate-cert: empty issuer");
                if (res.getValidatedAt() == null || res.getValidatedAt().isEmpty())
                    fail("validate-cert: empty validated_at");
                System.out.println("OK cert subject="
                    + res.getSubject().substring(0, Math.min(24, res.getSubject().length()))
                    + "… qualified=" + res.isQualified());
                break;
            }
            default:
                fail("unknown command: " + cmd);
        }
    }

    private Smoke() {}
}
