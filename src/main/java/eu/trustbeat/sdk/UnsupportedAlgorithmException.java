package eu.trustbeat.sdk;

/**
 * Thrown when a proof declares a {@code merkle_algorithm} this SDK version does
 * not implement.
 *
 * <p>Deliberately not a {@link VerificationException} and never a {@code false}
 * return: "I cannot check this proof" must not be mistaken for "this proof is
 * forged". Upgrade the SDK, or verify server-side via the API.
 */
public class UnsupportedAlgorithmException extends TrustBeatException {

    public UnsupportedAlgorithmException(String message) {
        super(message);
    }
}
