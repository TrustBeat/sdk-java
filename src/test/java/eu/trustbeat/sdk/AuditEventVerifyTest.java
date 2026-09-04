package eu.trustbeat.sdk;

import eu.trustbeat.sdk.internal.ApiClient;
import eu.trustbeat.sdk.internal.MerkleVerifier;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Local verification of audit event proofs, and the compatibility rule that
 * matters most: a proof from a server older than API 1.46 has no merkle_root and
 * must be reported as "cannot check" rather than "invalid".
 */
class AuditEventVerifyTest {

    private static byte[] sha(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int i = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, i, p.length); i += p.length; }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static AuditEventProof rfc6962Proof(String rootOverride, String algorithmOverride) {
        byte[] a  = sha("audit-a".getBytes());
        byte[] b  = sha("audit-b".getBytes());
        byte[] la = sha(concat(new byte[]{0x00}, a));
        byte[] lb = sha(concat(new byte[]{0x00}, b));
        byte[] root = sha(concat(new byte[]{0x01}, la, lb));
        return new AuditEventProof(
            "evt_1", hex(a), "batch_1", 0,
            List.of(new AuditProofStep(hex(lb), "right")),
            "2026-01-01T00:00:00Z",
            rootOverride != null ? rootOverride : hex(root),
            2,
            algorithmOverride != null ? algorithmOverride : MerkleAlgorithm.RFC6962_SHA256);
    }

    @Test
    void aValidRfc6962AuditProofVerifies() {
        assertTrue(MerkleVerifier.verifyAuditEvent(rfc6962Proof(null, null)));
    }

    @Test
    void aTamperedRootDoesNotVerify() {
        assertFalse(MerkleVerifier.verifyAuditEvent(rfc6962Proof("aa".repeat(32), null)));
    }

    @Test
    void aLegacyAuditProofVerifiesUnderTheLegacyFold() {
        byte[] a = sha("audit-a".getBytes());
        byte[] b = sha("audit-b".getBytes());
        String root = hex(sha(concat(a, b)));
        AuditEventProof p = new AuditEventProof(
            "evt_1", hex(a), "batch_1", 0,
            List.of(new AuditProofStep(hex(b), "right")),
            "2026-01-01T00:00:00Z", root, 2, MerkleAlgorithm.LEGACY_SHA256);
        assertTrue(MerkleVerifier.verifyAuditEvent(p));
    }

    // ── Compatibility with the API currently in production ──────────────────

    /** Exactly what api.trustbeat.eu returns today: no merkle_root, tree_size or algorithm. */
    private static AuditEventProof oldServerProof() {
        return ApiClient.parseAuditEventProof(Map.of(
            "event_id",       "evt_old",
            "canonical_hash", "ab".repeat(32),
            "batch_id",       "batch_old",
            "leaf_index",     0,
            "merkle_path",    List.of(Map.of("sibling", "cd".repeat(32), "side", "right")),
            "anchored_at",    "2026-01-01T00:00:00Z"));
    }

    @Test
    void anOldServerProofStillParsesAndDefaultsToLegacy() {
        AuditEventProof p = oldServerProof();
        assertEquals("evt_old", p.getEventId());
        assertEquals(1, p.getMerklePath().size());
        assertNull(p.getMerkleRoot());
        assertNull(p.getTreeSize());
        assertEquals(MerkleAlgorithm.LEGACY_SHA256, p.getMerkleAlgorithm());
    }

    @Test
    void anOldServerProofIsIncompleteNotInvalid() {
        // Returning false here would tell a customer their perfectly good audit
        // proof had been tampered with.
        IncompleteProofException e = assertThrows(IncompleteProofException.class,
            () -> MerkleVerifier.verifyAuditEvent(oldServerProof()));
        // Not a VerificationException — the two are unrelated types, which javac
        // enforces so strictly that `e instanceof VerificationException` will not
        // even compile. Stated here so the intent survives a refactor.
        assertFalse(VerificationException.class.isAssignableFrom(IncompleteProofException.class));
        assertTrue(e.getMessage().contains("merkle_root"));
    }

    @Test
    void anUnknownAlgorithmIsUnsupportedNotInvalid() {
        assertThrows(UnsupportedAlgorithmException.class,
            () -> MerkleVerifier.verifyAuditEvent(rfc6962Proof(null, "sha3-future")));
    }

    @Test
    void theLegacyConstructorStillCompilesAndMeansOldServer() {
        // Source compatibility for anyone who built one by hand under 0.3.0.
        AuditEventProof p = new AuditEventProof(
            "evt", "ab".repeat(32), "b", 0, List.of(), "2026-01-01T00:00:00Z");
        assertNull(p.getMerkleRoot());
        assertEquals(MerkleAlgorithm.LEGACY_SHA256, p.getMerkleAlgorithm());
    }
}
