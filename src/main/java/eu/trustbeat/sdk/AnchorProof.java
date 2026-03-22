package eu.trustbeat.sdk;

import java.util.List;

/**
 * Full Merkle inclusion proof, returned once anchoring is complete.
 * Use {@link TrustBeat#verify} to verify the proof locally.
 */
public final class AnchorProof {

    private final String         id;
    private final String         hash;
    private final String         hashAlgorithm;
    private final String         batchId;
    private final int            leafIndex;
    private final String         merkleRoot;
    private final List<ProofStep> proofPath;
    /** Raw DER-encoded RFC 3161 TimeStampToken bytes. */
    private final byte[]         token;
    private final String         tokenFormat;
    private final String         tsaSerial;
    private final String         provider;
    private final String         anchoredAt;
    private final String         clientRef;
    private final String         description;

    public AnchorProof(String id, String hash, String hashAlgorithm,
                       String batchId, int leafIndex, String merkleRoot,
                       List<ProofStep> proofPath, byte[] token,
                       String tokenFormat, String tsaSerial, String provider,
                       String anchoredAt, String clientRef, String description) {
        this.id            = id;
        this.hash          = hash;
        this.hashAlgorithm = hashAlgorithm;
        this.batchId       = batchId;
        this.leafIndex     = leafIndex;
        this.merkleRoot    = merkleRoot;
        this.proofPath     = proofPath;
        this.token         = token;
        this.tokenFormat   = tokenFormat;
        this.tsaSerial     = tsaSerial;
        this.provider      = provider;
        this.anchoredAt    = anchoredAt;
        this.clientRef     = clientRef;
        this.description   = description;
    }

    public String          getId()            { return id; }
    public String          getHash()          { return hash; }
    public String          getHashAlgorithm() { return hashAlgorithm; }
    public String          getBatchId()       { return batchId; }
    public int             getLeafIndex()     { return leafIndex; }
    public String          getMerkleRoot()    { return merkleRoot; }
    public List<ProofStep> getProofPath()     { return proofPath; }
    public byte[]          getToken()         { return token; }
    public String          getTokenFormat()   { return tokenFormat; }
    public String          getTsaSerial()     { return tsaSerial; }
    public String          getProvider()      { return provider; }
    public String          getAnchoredAt()    { return anchoredAt; }
    public String          getClientRef()     { return clientRef; }
    public String          getDescription()   { return description; }

    @Override
    public String toString() {
        return "AnchorProof{id='" + id + "', merkleRoot='" + merkleRoot + "'}";
    }
}
