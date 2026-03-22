package eu.trustbeat.sdk.internal;

import eu.trustbeat.sdk.AnchorProof;
import eu.trustbeat.sdk.ProofStep;
import eu.trustbeat.sdk.VerificationException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Local Merkle inclusion proof verifier.
 *
 * Mirrors MerkleEngine.scala exactly:
 *   parent = SHA-256(left_child || right_child)
 *   side="left"  → sibling on the left  → hash(sibling || current)
 *   side="right" → sibling on the right → hash(current || sibling)
 *   Odd layers duplicate the last node.
 */
public final class MerkleVerifier {

    private MerkleVerifier() {}

    /**
     * Verify a Merkle inclusion proof locally.
     *
     * @return true if the computed root matches proof.getMerkleRoot(), false otherwise
     * @throws VerificationException if the proof data is malformed (bad hex, unknown side)
     */
    public static boolean verify(AnchorProof proof) {
        byte[] current = decodeHex(proof.getHash(), "Invalid leaf hash");
        byte[] expected = decodeHex(proof.getMerkleRoot(), "Invalid merkle_root");

        for (ProofStep step : proof.getProofPath()) {
            byte[] sibling = decodeHex(step.getSibling(), "Invalid sibling hex");
            switch (step.getSide()) {
                case "left":
                    // sibling is on the left: parent = hash(sibling || current)
                    current = sha256(concat(sibling, current));
                    break;
                case "right":
                    // sibling is on the right: parent = hash(current || sibling)
                    current = sha256(concat(current, sibling));
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
