package eu.trustbeat.sdk;

/**
 * Wire names of the Merkle constructions a proof can declare.
 *
 * <p>A proof is only meaningful together with the algorithm that produced it, so
 * every proof carries this discriminator. A proof issued before the field existed
 * omits it, and those are all {@link #LEGACY_SHA256}.
 */
public final class MerkleAlgorithm {

    private MerkleAlgorithm() {}

    /**
     * The original TrustBeat tree: the leaf is your hash unchanged, parents are
     * {@code SHA-256(left || right)}, and an odd node is duplicated to complete
     * its pair.
     */
    public static final String LEGACY_SHA256 = "trustbeat-legacy-sha256";

    /**
     * RFC 6962 / RFC 9162: leaves are {@code SHA-256(0x00 || entry)}, parents are
     * {@code SHA-256(0x01 || left || right)}, and a layer splits at the largest
     * power of two below its size instead of duplicating.
     */
    public static final String RFC6962_SHA256 = "rfc6962-sha256";
}
