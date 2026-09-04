package eu.trustbeat.sdk;

/**
 * Thrown when a proof does not carry the fields needed to check it locally.
 *
 * <p>Audit event proofs from servers older than API 1.46 have no
 * {@code merkle_root}, so there is nothing to fold the path against. Like
 * {@link UnsupportedAlgorithmException} this is deliberately not a
 * {@link VerificationException} and never a {@code false} return: "I cannot
 * check this proof" must not be mistaken for "this proof is forged". Verify
 * server-side via the API, or upgrade the server.
 */
public class IncompleteProofException extends TrustBeatException {

    public IncompleteProofException(String message) {
        super(message);
    }
}
