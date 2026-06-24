package eu.trustbeat.sdk;

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

    public static void main(String[] args) {
        if (args.length < 1) fail("usage: Smoke {submit|verify <id>|submit-batch|verify-batch <id>}");
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
            default:
                fail("unknown command: " + cmd);
        }
    }

    private Smoke() {}
}
