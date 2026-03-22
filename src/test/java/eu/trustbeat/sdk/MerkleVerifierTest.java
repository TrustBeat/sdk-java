package eu.trustbeat.sdk;

import eu.trustbeat.sdk.internal.MerkleVerifier;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for local Merkle proof verification.
 *
 * Test vectors are derived from the MerkleEngine algorithm:
 *   parent = SHA-256(left_child || right_child)
 *   odd layers duplicate the last node.
 */
class MerkleVerifierTest {

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] combine(byte[] a, byte[] b) {
        byte[] merged = new byte[a.length + b.length];
        System.arraycopy(a, 0, merged, 0,        a.length);
        System.arraycopy(b, 0, merged, a.length, b.length);
        return sha256(merged);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static AnchorProof makeProof(byte[] leaf, List<ProofStep> path, byte[] root) {
        return new AnchorProof(
            "test-id", hex(leaf), "sha256",
            "batch-1", 0, hex(root),
            path, new byte[0], "rfc3161", "0",
            "test", "2026-01-01T00:00:00Z", null, null
        );
    }

    // ── 4-leaf tree test vectors ──────────────────────────────────────────────
    //
    //  leaves:  L0   L1   L2   L3
    //  layer1:  N01=H(L0,L1)   N23=H(L2,L3)
    //  root:    R  =H(N01,N23)

    static final byte[] L0   = sha256("leaf0".getBytes());
    static final byte[] L1   = sha256("leaf1".getBytes());
    static final byte[] L2   = sha256("leaf2".getBytes());
    static final byte[] L3   = sha256("leaf3".getBytes());
    static final byte[] N01  = combine(L0, L1);
    static final byte[] N23  = combine(L2, L3);
    static final byte[] ROOT4 = combine(N01, N23);

    @Test
    void leaf0ProofIsValid() {
        List<ProofStep> path = Arrays.asList(
            new ProofStep(hex(L1),  "right"),
            new ProofStep(hex(N23), "right")
        );
        assertTrue(MerkleVerifier.verify(makeProof(L0, path, ROOT4)));
    }

    @Test
    void leaf1ProofIsValid() {
        List<ProofStep> path = Arrays.asList(
            new ProofStep(hex(L0),  "left"),
            new ProofStep(hex(N23), "right")
        );
        assertTrue(MerkleVerifier.verify(makeProof(L1, path, ROOT4)));
    }

    @Test
    void leaf2ProofIsValid() {
        List<ProofStep> path = Arrays.asList(
            new ProofStep(hex(L3),  "right"),
            new ProofStep(hex(N01), "left")
        );
        assertTrue(MerkleVerifier.verify(makeProof(L2, path, ROOT4)));
    }

    @Test
    void leaf3ProofIsValid() {
        List<ProofStep> path = Arrays.asList(
            new ProofStep(hex(L2),  "left"),
            new ProofStep(hex(N01), "left")
        );
        assertTrue(MerkleVerifier.verify(makeProof(L3, path, ROOT4)));
    }

    @Test
    void wrongSiblingReturnsFalse() {
        List<ProofStep> path = Arrays.asList(
            new ProofStep(hex(L2),  "right"),  // wrong sibling
            new ProofStep(hex(N23), "right")
        );
        assertFalse(MerkleVerifier.verify(makeProof(L0, path, ROOT4)));
    }

    @Test
    void wrongRootReturnsFalse() {
        List<ProofStep> path = Arrays.asList(
            new ProofStep(hex(L1),  "right"),
            new ProofStep(hex(N23), "right")
        );
        AnchorProof proof = new AnchorProof(
            "test-id", hex(L0), "sha256",
            "batch-1", 0, "ff".repeat(32),
            path, new byte[0], "rfc3161", "0",
            "test", "2026-01-01T00:00:00Z", null, null
        );
        assertFalse(MerkleVerifier.verify(proof));
    }

    @Test
    void swappedSideReturnsFalse() {
        List<ProofStep> path = Arrays.asList(
            new ProofStep(hex(L1),  "left"),   // wrong side
            new ProofStep(hex(N23), "right")
        );
        assertFalse(MerkleVerifier.verify(makeProof(L0, path, ROOT4)));
    }

    // ── Single-leaf tree ──────────────────────────────────────────────────────

    @Test
    void singleLeafEmptyPathRootEqualsLeaf() {
        byte[] leaf = sha256("only leaf".getBytes());
        AnchorProof proof = makeProof(leaf, Collections.emptyList(), leaf);
        assertTrue(MerkleVerifier.verify(proof));
    }

    // ── Odd-leaf (3-leaf) tree ────────────────────────────────────────────────
    //   La  Lb  Lc  (Lc duplicated)
    //   Nab=H(La,Lb)  Ncc=H(Lc,Lc)
    //   ROOT=H(Nab,Ncc)

    @Test
    void oddLeafTreeWithDuplicateIsValid() {
        byte[] La   = sha256("a".getBytes());
        byte[] Lb   = sha256("b".getBytes());
        byte[] Lc   = sha256("c".getBytes());
        byte[] Nab  = combine(La, Lb);
        byte[] Ncc  = combine(Lc, Lc);
        byte[] root = combine(Nab, Ncc);
        List<ProofStep> path = Arrays.asList(
            new ProofStep(hex(Lc),  "right"),  // duplicate sibling
            new ProofStep(hex(Nab), "left")
        );
        assertTrue(MerkleVerifier.verify(makeProof(Lc, path, root)));
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    @Test
    void malformedLeafHashThrowsVerificationException() {
        AnchorProof proof = new AnchorProof(
            "test-id", "not-hex!!", "sha256",
            "batch-1", 0, hex(ROOT4),
            Collections.emptyList(), new byte[0], "rfc3161", "0",
            "test", "2026-01-01T00:00:00Z", null, null
        );
        VerificationException ex = assertThrows(VerificationException.class,
            () -> MerkleVerifier.verify(proof));
        assertTrue(ex.getMessage().contains("Invalid leaf hash"));
    }

    @Test
    void malformedSiblingThrowsVerificationException() {
        List<ProofStep> path = Collections.singletonList(
            new ProofStep("gg".repeat(32), "right")
        );
        AnchorProof proof = makeProof(L0, path, ROOT4);
        VerificationException ex = assertThrows(VerificationException.class,
            () -> MerkleVerifier.verify(proof));
        assertTrue(ex.getMessage().contains("Invalid sibling hex"));
    }

    @Test
    void unknownSideThrowsVerificationException() {
        List<ProofStep> path = Collections.singletonList(
            new ProofStep(hex(L1), "center")
        );
        AnchorProof proof = makeProof(L0, path, ROOT4);
        VerificationException ex = assertThrows(VerificationException.class,
            () -> MerkleVerifier.verify(proof));
        assertTrue(ex.getMessage().contains("Unknown side"));
    }

    @Test
    void malformedMerkleRootThrowsVerificationException() {
        AnchorProof proof = new AnchorProof(
            "test-id", hex(L0), "sha256",
            "batch-1", 0, "zzzz",
            Collections.emptyList(), new byte[0], "rfc3161", "0",
            "test", "2026-01-01T00:00:00Z", null, null
        );
        VerificationException ex = assertThrows(VerificationException.class,
            () -> MerkleVerifier.verify(proof));
        assertTrue(ex.getMessage().contains("Invalid merkle_root"));
    }
}
