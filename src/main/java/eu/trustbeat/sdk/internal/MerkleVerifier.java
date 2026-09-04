package eu.trustbeat.sdk.internal;

import eu.trustbeat.sdk.AnchorProof;
import eu.trustbeat.sdk.MerkleAlgorithm;
import eu.trustbeat.sdk.ProofStep;
import eu.trustbeat.sdk.UnsupportedAlgorithmException;
import eu.trustbeat.sdk.VerificationException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Local Merkle inclusion proof verifier.
 *
 * The fold depends on the construction the proof declares:
 *   trustbeat-legacy-sha256 — leaf = your hash, parent = SHA-256(left || right)
 *   rfc6962-sha256          — leaf = SHA-256(0x00 || your hash),
 *                             parent = SHA-256(0x01 || left || right)
 *
 * In both, side gives the sibling's position:
 *   side="left"  → sibling on the left  → hash over (sibling, current)
 *   side="right" → sibling on the right → hash over (current, sibling)
 */
public final class MerkleVerifier {

    private MerkleVerifier() {}

    /**
     * Verify a Merkle inclusion proof locally.
     *
     * @return true if the computed root matches proof.getMerkleRoot(), false otherwise
     * @throws VerificationException if the proof data is malformed (bad hex, unknown side)
     * @throws UnsupportedAlgorithmException if this SDK cannot compute the declared algorithm
     */
    /**
     * Verify an audit event's Merkle inclusion proof locally.
     *
     * <p>The audit counterpart of {@link #verify(AnchorProof)}, for the shape that
     * names the leaf {@code canonicalHash} and the path {@code merklePath}.
     *
     * @return true if the computed root matches, false otherwise
     * @throws IncompleteProofException if the proof carries no {@code merkleRoot} —
     *         servers before API 1.46 did not send one, so there is nothing to fold
     *         against. That is "cannot check", never "invalid".
     * @throws VerificationException if the proof data is malformed
     * @throws UnsupportedAlgorithmException if this SDK cannot compute the algorithm
     */
    public static boolean verifyAuditEvent(eu.trustbeat.sdk.AuditEventProof proof) {
        if (proof.getMerkleRoot() == null || proof.getMerkleRoot().isEmpty()) {
            throw new eu.trustbeat.sdk.IncompleteProofException(
                "This audit event proof has no merkle_root, so it cannot be folded "
                    + "locally. The server that issued it predates API 1.46. Verify it "
                    + "server-side via the API, or re-fetch it from an upgraded server.");
        }
        java.util.List<eu.trustbeat.sdk.ProofStep> path = new java.util.ArrayList<>();
        for (eu.trustbeat.sdk.AuditProofStep s : proof.getMerklePath()) {
            path.add(new eu.trustbeat.sdk.ProofStep(s.getSibling(), s.getSide()));
        }
        // Reuse the anchor fold: the shapes differ only in field names.
        return verify(new AnchorProof(
            null, proof.getCanonicalHash(), "SHA-256", proof.getBatchId(), proof.getLeafIndex(),
            proof.getMerkleRoot(), path, new byte[0], "", "", "", proof.getAnchoredAt(),
            null, null, proof.getMerkleAlgorithm(), proof.getTreeSize()));
    }

    public static boolean verify(AnchorProof proof) {
        String algorithm = proof.getMerkleAlgorithm() == null || proof.getMerkleAlgorithm().isEmpty()
            ? MerkleAlgorithm.LEGACY_SHA256
            : proof.getMerkleAlgorithm();

        final byte[] leafPrefix;
        final byte[] nodePrefix;
        if (MerkleAlgorithm.LEGACY_SHA256.equals(algorithm)) {
            leafPrefix = new byte[0];
            nodePrefix = new byte[0];
        } else if (MerkleAlgorithm.RFC6962_SHA256.equals(algorithm)) {
            leafPrefix = new byte[] { 0x00 };
            nodePrefix = new byte[] { 0x01 };
        } else {
            throw new UnsupportedAlgorithmException(
                "Unsupported merkle_algorithm \"" + algorithm + "\". This SDK understands \""
                    + MerkleAlgorithm.LEGACY_SHA256 + "\" and \"" + MerkleAlgorithm.RFC6962_SHA256
                    + "\". Upgrade the SDK, or verify via the API.");
        }

        byte[] current = decodeHex(proof.getHash(), "Invalid leaf hash");
        byte[] expected = decodeHex(proof.getMerkleRoot(), "Invalid merkle_root");
        if (leafPrefix.length > 0) current = sha256(concat(leafPrefix, current));

        for (ProofStep step : proof.getProofPath()) {
            byte[] sibling = decodeHex(step.getSibling(), "Invalid sibling hex");
            switch (step.getSide()) {
                case "left":
                    // sibling is on the left
                    current = sha256(concat(nodePrefix, concat(sibling, current)));
                    break;
                case "right":
                    // sibling is on the right
                    current = sha256(concat(nodePrefix, concat(current, sibling)));
                    break;
                default:
                    throw new VerificationException(
                        "Unknown side: \"" + step.getSide() + "\" — expected \"left\" or \"right\"");
            }
        }

        return timingSafeEqual(current, expected);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] decodeHex(String hex, String label) {
        if (hex == null || hex.length() % 2 != 0 || !hex.matches("[0-9a-fA-F]*")) {
            throw new VerificationException(label + ": \"" + hex + "\"");
        }
        try {
            return HexFormat.of().parseHex(hex.toLowerCase());
        } catch (IllegalArgumentException e) {
            throw new VerificationException(label + ": \"" + hex + "\"");
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0,        a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Constant-time comparison to resist timing attacks. */
    private static boolean timingSafeEqual(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
