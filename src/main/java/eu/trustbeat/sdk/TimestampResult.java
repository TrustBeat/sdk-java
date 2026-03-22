package eu.trustbeat.sdk;

/**
 * Result of a direct (non-Merkle) qualified timestamp call.
 * Returned by {@link TrustBeat#timestamp}.
 */
public final class TimestampResult {

    private final String id;
    private final String hash;
    private final String hashAlgorithm;
    /** Raw DER-encoded RFC 3161 TimeStampToken bytes. */
    private final byte[] token;
    private final String tokenFormat;
    private final String tsaSerial;
    private final String provider;
    private final String timestampedAt;

    public TimestampResult(String id, String hash, String hashAlgorithm,
                           byte[] token, String tokenFormat, String tsaSerial,
                           String provider, String timestampedAt) {
        this.id            = id;
        this.hash          = hash;
        this.hashAlgorithm = hashAlgorithm;
        this.token         = token;
        this.tokenFormat   = tokenFormat;
        this.tsaSerial     = tsaSerial;
        this.provider      = provider;
        this.timestampedAt = timestampedAt;
    }

    public String getId()            { return id; }
    public String getHash()          { return hash; }
    public String getHashAlgorithm() { return hashAlgorithm; }
    public byte[] getToken()         { return token; }
    public String getTokenFormat()   { return tokenFormat; }
    public String getTsaSerial()     { return tsaSerial; }
    public String getProvider()      { return provider; }
    public String getTimestampedAt() { return timestampedAt; }

    @Override
    public String toString() {
        return "TimestampResult{id='" + id + "', tsaSerial='" + tsaSerial + "'}";
    }
}
