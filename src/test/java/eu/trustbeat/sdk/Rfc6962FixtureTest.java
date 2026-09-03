package eu.trustbeat.sdk;

import eu.trustbeat.sdk.internal.MerkleVerifier;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Agreement with tests/fixtures/rfc6962-proofs.json.
 *
 * <p>The same file is checked by the Scala engine and by every other SDK, so this
 * pins cross-implementation agreement rather than self-consistency.
 */
class Rfc6962FixtureTest {

    private static String fixture() throws IOException {
        Path dir = Path.of("").toAbsolutePath();
        for (int i = 0; i < 8 && dir != null; i++, dir = dir.getParent()) {
            Path f = dir.resolve("tests/fixtures/rfc6962-proofs.json");
            if (Files.exists(f)) return Files.readString(f);
        }
        throw new AssertionError("rfc6962-proofs.json not found");
    }

    /** Minimal extraction — avoids adding a JSON dependency to a zero-dependency SDK. */
    private static List<AnchorProof> parse(String json, String hashOverride) {
        List<AnchorProof> out = new ArrayList<>();
        Matcher m = Pattern.compile("\\{\\s*\"id\": \"leaf-\\d+\".*?\"tree_size\": \\d+\\s*\\}", Pattern.DOTALL)
                           .matcher(json);
        while (m.find()) {
            String o = m.group();
            String hash = hashOverride != null ? hashOverride : grab(o, "\"hash\": \"([0-9a-f]+)\"");
            String root = grab(o, "\"merkle_root\": \"([0-9a-f]+)\"");
            String alg  = grab(o, "\"merkle_algorithm\": \"([^\"]+)\"");
            List<ProofStep> steps = new ArrayList<>();
            Matcher sm = Pattern.compile("\"sibling\": \"([0-9a-f]+)\",\\s*\"side\": \"(left|right)\"").matcher(o);
            while (sm.find()) steps.add(new ProofStep(sm.group(1), sm.group(2)));
            out.add(new AnchorProof("id", hash, "SHA-256", "b", 0, root, steps, new byte[0],
                "RFC3161_DER", "1", "fixture", "2026-01-01T00:00:00Z", null, null, alg, null));
        }
        return out;
    }

    private static String grab(String s, String re) {
        Matcher m = Pattern.compile(re).matcher(s);
        assertTrue(m.find(), "pattern not found: " + re);
        return m.group(1);
    }

    @Test
    void everyFixtureProofVerifies() throws IOException {
        List<AnchorProof> proofs = parse(fixture(), null);
        assertEquals(7, proofs.size(), "fixture should hold 7 proofs");
        for (int i = 0; i < proofs.size(); i++) {
            assertTrue(MerkleVerifier.verify(proofs.get(i)), "leaf " + i + " failed");
        }
    }

    @Test
    void aTamperedFixtureProofFails() throws IOException {
        // Guards against the suite passing because verification is a no-op.
        List<AnchorProof> proofs = parse(fixture(), "00".repeat(32));
        assertFalse(MerkleVerifier.verify(proofs.get(0)));
    }
}
