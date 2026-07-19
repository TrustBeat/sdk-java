package eu.trustbeat.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Webhook signature verification — no network call.
 * <p>
 * TrustBeat signs every webhook delivery for accounts with a webhook secret
 * configured. Each request carries the header:
 * <pre>X-TrustBeat-Signature: t=&lt;unix_ts&gt;,v1=&lt;hex(HMAC-SHA256(secret, "&lt;ts&gt;.&lt;body&gt;"))&gt;</pre>
 * <p>
 * The HMAC key is the UTF-8 bytes of the secret string exactly as shown in
 * the dashboard (it is <b>not</b> hex-decoded first). The signed payload is
 * the ASCII timestamp, a literal {@code .}, and the raw request body bytes.
 * <p>
 * A constant-time comparison is used for the signature check. The timestamp
 * bounds the window for replaying a captured delivery (default 5 minutes).
 */
public final class WebhookVerifier {

    /** Default replay tolerance: 5 minutes. */
    public static final long DEFAULT_TOLERANCE_SECS = 300;

    private WebhookVerifier() {}

    /**
     * Verify the {@code X-TrustBeat-Signature} header of a webhook delivery
     * using the default 5-minute tolerance and the current wall-clock time.
     *
     * Pass the <b>raw request body</b> exactly as received — do not
     * re-serialize the JSON, as any formatting difference changes the signature.
     *
     * @param payload         raw request body bytes as received
     * @param signatureHeader value of the {@code X-TrustBeat-Signature} header
     * @param secret          webhook secret from your TrustBeat dashboard
     * @return {@code true} if the signature is valid and the timestamp is
     *         within tolerance; {@code false} on mismatch or possible replay
     * @throws VerificationException if the header or secret is malformed
     */
    public static boolean verifyWebhookSignature(byte[] payload, String signatureHeader, String secret) {
        return verifyWebhookSignature(payload, signatureHeader, secret,
            DEFAULT_TOLERANCE_SECS, System.currentTimeMillis() / 1000L);
    }

    /**
     * Verify with an explicit tolerance and clock — see
     * {@link #verifyWebhookSignature(byte[], String, String)}.
     *
     * @param toleranceSecs max allowed |now - t| in seconds
     * @param nowEpochSecs  current unix time (injectable for testing)
     */
    public static boolean verifyWebhookSignature(
            byte[] payload, String signatureHeader, String secret,
            long toleranceSecs, long nowEpochSecs) {
        if (secret == null || secret.isEmpty())
            throw new VerificationException("Webhook secret must not be empty");
        if (signatureHeader == null || signatureHeader.isEmpty())
            throw new VerificationException("Signature header must not be empty");

        String tsStr = null;
        String sigHex = null;
        for (String part : signatureHeader.split(",")) {
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            String key = part.substring(0, eq).trim();
            String value = part.substring(eq + 1);
            if ("t".equals(key)) tsStr = value;
            else if ("v1".equals(key)) sigHex = value;
        }
        if (tsStr == null || tsStr.isEmpty() || sigHex == null || sigHex.isEmpty())
            throw new VerificationException(
                "Malformed signature header (expected 't=<ts>,v1=<hex>'): " + signatureHeader);
        long ts;
        try {
            ts = Long.parseLong(tsStr);
        } catch (NumberFormatException e) {
            throw new VerificationException("Malformed signature timestamp: " + tsStr);
        }

        if (Math.abs(nowEpochSecs - ts) > toleranceSecs) return false;

        byte[] expected = hmacSha256Hex(secret, tsStr, payload);
        byte[] provided = sigHex.toLowerCase().getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, provided);
    }

    private static byte[] hmacSha256Hex(String secret, String tsStr, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(tsStr.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) '.');
            mac.update(payload);
            byte[] digest = mac.doFinal();
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) hex.append(String.format("%02x", b));
            return hex.toString().getBytes(StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new VerificationException("HMAC-SHA256 unavailable: " + e.getMessage());
        }
    }
}
