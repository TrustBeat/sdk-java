package eu.trustbeat.sdk;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for webhook signature verification — fully offline.
 *
 * Signatures are constructed exactly the way the server builds them
 * (WebhookDispatcher.scala): hex(HMAC-SHA256(utf8(secret), "&lt;ts&gt;.&lt;body&gt;")).
 */
class WebhookVerifierTest {

    private static final String SECRET = "ab".repeat(32); // key = UTF-8 bytes, not decoded hex
    private static final byte[] BODY =
        "{\"event\":\"anchor.completed\",\"id\":\"track-1\",\"hash\":\"aa\"}"
            .getBytes(StandardCharsets.UTF_8);
    private static final long NOW = 1_752_000_000L;

    private static String sign(byte[] body, byte[] key, long ts) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(Long.toString(ts).getBytes(StandardCharsets.US_ASCII));
        mac.update((byte) '.');
        mac.update(body);
        StringBuilder hex = new StringBuilder();
        for (byte b : mac.doFinal()) hex.append(String.format("%02x", b));
        return "t=" + ts + ",v1=" + hex;
    }

    private static String sign(byte[] body, long ts) throws Exception {
        return sign(body, SECRET.getBytes(StandardCharsets.UTF_8), ts);
    }

    @Test
    void validSignatureAccepted() throws Exception {
        assertTrue(WebhookVerifier.verifyWebhookSignature(BODY, sign(BODY, NOW), SECRET, 300, NOW));
    }

    @Test
    void keyIsUtf8OfSecretNotDecodedHex() throws Exception {
        // Signing with the hex-decoded secret must NOT verify.
        byte[] decoded = new byte[SECRET.length() / 2];
        for (int i = 0; i < decoded.length; i++)
            decoded[i] = (byte) Integer.parseInt(SECRET.substring(2 * i, 2 * i + 2), 16);
        String header = sign(BODY, decoded, NOW);
        assertFalse(WebhookVerifier.verifyWebhookSignature(BODY, header, SECRET, 300, NOW));
    }

    @Test
    void tamperedPayloadRejected() throws Exception {
        String header = sign(BODY, NOW);
        byte[] tampered = new String(BODY, StandardCharsets.UTF_8)
            .replace("track-1", "track-2").getBytes(StandardCharsets.UTF_8);
        assertFalse(WebhookVerifier.verifyWebhookSignature(tampered, header, SECRET, 300, NOW));
    }

    @Test
    void wrongSecretRejected() throws Exception {
        assertFalse(WebhookVerifier.verifyWebhookSignature(BODY, sign(BODY, NOW), "cd".repeat(32), 300, NOW));
    }

    @Test
    void uppercaseHexAccepted() throws Exception {
        String header = sign(BODY, NOW);
        int v1 = header.indexOf("v1=") + 3;
        String upper = header.substring(0, v1) + header.substring(v1).toUpperCase();
        assertTrue(WebhookVerifier.verifyWebhookSignature(BODY, upper, SECRET, 300, NOW));
    }

    // ── Replay window ─────────────────────────────────────────────────────────

    @Test
    void staleTimestampRejected() throws Exception {
        assertFalse(WebhookVerifier.verifyWebhookSignature(BODY, sign(BODY, NOW - 301), SECRET, 300, NOW));
    }

    @Test
    void futureTimestampRejected() throws Exception {
        assertFalse(WebhookVerifier.verifyWebhookSignature(BODY, sign(BODY, NOW + 301), SECRET, 300, NOW));
    }

    @Test
    void toleranceBoundaryAccepted() throws Exception {
        assertTrue(WebhookVerifier.verifyWebhookSignature(BODY, sign(BODY, NOW - 300), SECRET, 300, NOW));
    }

    @Test
    void customToleranceHonoured() throws Exception {
        String header = sign(BODY, NOW - 500);
        assertFalse(WebhookVerifier.verifyWebhookSignature(BODY, header, SECRET, 300, NOW));
        assertTrue(WebhookVerifier.verifyWebhookSignature(BODY, header, SECRET, 600, NOW));
    }

    // ── Malformed input ───────────────────────────────────────────────────────

    @Test
    void malformedHeaderThrows() {
        for (String bad : new String[] {"", "v1=abc", "t=123", "t=abc,v1=def", "nonsense"}) {
            assertThrows(VerificationException.class,
                () -> WebhookVerifier.verifyWebhookSignature(BODY, bad, SECRET, 300, NOW),
                "header: " + bad);
        }
    }

    @Test
    void emptySecretThrows() throws Exception {
        String header = sign(BODY, NOW);
        assertThrows(VerificationException.class,
            () -> WebhookVerifier.verifyWebhookSignature(BODY, header, "", 300, NOW));
    }

    @Test
    void extraHeaderPartsTolerated() throws Exception {
        // Future-proofing: unknown scheme versions (e.g. v2=…) must not break v1.
        String header = sign(BODY, NOW) + ",v2=futurestuff";
        assertTrue(WebhookVerifier.verifyWebhookSignature(BODY, header, SECRET, 300, NOW));
    }

    // ── Client static method ──────────────────────────────────────────────────

    @Test
    void clientStaticMethodDelegates() throws Exception {
        long fresh = System.currentTimeMillis() / 1000L;
        assertTrue(TrustBeat.verifyWebhookSignature(BODY, sign(BODY, fresh), SECRET));
    }
}
