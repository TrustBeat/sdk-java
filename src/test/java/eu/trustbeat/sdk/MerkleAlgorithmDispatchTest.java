package eu.trustbeat.sdk;

import eu.trustbeat.sdk.internal.MerkleVerifier;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Verification dispatch on the proof's declared merkle_algorithm (SDK 0.4.0). */
class MerkleAlgorithmDispatchTest {

    private static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) md.update(p);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

    private static AnchorProof proof(String hash, String root, List<ProofStep> path, String algorithm) {
        return new AnchorProof(
            "p1", hash, "SHA-256", "b1", 0, root,
            path, new byte[0], "RFC3161_DER", "1",
            "test", "2026-01-01T00:00:00Z", null, null,
            algorithm, null
        );
    }

    @Test
    void nullAlgorithmIsLegacy() {
        // Proofs issued before the field existed must keep verifying forever.
        byte[] leaf = sha256("a".getBytes());
        AnchorProof p = proof(hex(leaf), hex(leaf), Collections.emptyList(), null);
        assertEquals(MerkleAlgorithm.LEGACY_SHA256, p.getMerkleAlgorithm());
        assertTrue(MerkleVerifier.verify(p));
    }

    @Test
    void legacyConstructorStillCompilesAndMeansLegacy() {
        // The 0.3.x 14-arg constructor is retained for source compatibility.
        byte[] leaf = sha256("a".getBytes());
        AnchorProof p = new AnchorProof(
            "p1", hex(leaf), "SHA-256", "b1", 0, hex(leaf),
            Collections.emptyList(), new byte[0], "RFC3161_DER", "1",
            "test", "2026-01-01T00:00:00Z", null, null);
        assertEquals(MerkleAlgorithm.LEGACY_SHA256, p.getMerkleAlgorithm());
        assertTrue(MerkleVerifier.verify(p));
    }

    @Test
    void rfc6962HashesTheLeaf() {
        byte[] leaf = sha256("a".getBytes());
        String rfcRoot = hex(sha256(new byte[] { 0x00 }, leaf));

        assertTrue(MerkleVerifier.verify(
            proof(hex(leaf), rfcRoot, Collections.emptyList(), MerkleAlgorithm.RFC6962_SHA256)));

        // Under rfc6962 a one-leaf root is not the leaf itself.
        assertFalse(MerkleVerifier.verify(
            proof(hex(leaf), hex(leaf), Collections.emptyList(), MerkleAlgorithm.RFC6962_SHA256)));
    }

    @Test
    void rfc6962ReferenceVector() {
        // MTH([SHA256("a"), SHA256("b"), SHA256("c")]) per RFC 6962, leaf 0.
        byte[] a = sha256("a".getBytes());
        List<ProofStep> path = Arrays.asList(
            new ProofStep("a0d9f0a50b35b9f7d7edc57fb64f4771ddef0fefeaca4e6f949a1514db5b136d", "right"),
            new ProofStep("6a3fc11b79f836bda340e75c8906e961b8adf4d6a08a2b992e3f38cd6ff38ebf", "right"));
        String root = "cac3d448d4e20a2ad5eae1f500e63c2a7f9217cd14572ba7fd22e26dc1ec2648";
        assertTrue(MerkleVerifier.verify(proof(hex(a), root, path, MerkleAlgorithm.RFC6962_SHA256)));
    }

    // Vectors below are taken verbatim from Google's transparency-dev/merkle
    // (rfc6962_test.go) — a third-party implementation. Our own arithmetic only
    // proves self-consistency; these prove conformance.
    private static final String UPSTREAM_ENTRY      = "4c313233343536"; // hex of "L123456"
    private static final String UPSTREAM_LEAF       = "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56";
    private static final String UPSTREAM_EMPTY_LEAF = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
    private static final String UPSTREAM_ROOT_2     = "bf9ae70442844df993ca0001a7c8a095c5f145857960b1ee389df6cbe84b5bf3";

    @Test
    void leafHashMatchesUpstreamVector() {
        // SHA-256(0x00 || "L123456") per transparency-dev/merkle.
        assertTrue(MerkleVerifier.verify(proof(
            UPSTREAM_ENTRY, UPSTREAM_LEAF, Collections.emptyList(), MerkleAlgorithm.RFC6962_SHA256)));
    }

    @Test
    void rfc6962LeftSiblingAppliesTheNodePrefix() {
        // Two-leaf tree whose BOTH leaf hashes are upstream vectors.
        // Exercises side="left", which no other rfc6962 test reaches.
        List<ProofStep> path = Collections.singletonList(
            new ProofStep(UPSTREAM_EMPTY_LEAF, "left"));
        assertTrue(MerkleVerifier.verify(proof(
            UPSTREAM_ENTRY, UPSTREAM_ROOT_2, path, MerkleAlgorithm.RFC6962_SHA256)));
    }

    @Test
    void unknownAlgorithmThrowsRatherThanReturningFalse() {
        // "I cannot check this" must not look like "this proof is forged".
        byte[] leaf = sha256("a".getBytes());
        assertThrows(UnsupportedAlgorithmException.class, () ->
            MerkleVerifier.verify(proof(hex(leaf), hex(leaf), Collections.emptyList(), "sha3-512-tree")));
    }
}
