package eu.trustbeat.sdk;

/** A deleted Signature Preservation record. Deletion is final; {@link #getPeoSha256()} stays in its batch's hash tree. */
public final class SignaturePreservationDeletion {
    private final String id, deletedAt, peoSha256;

    public SignaturePreservationDeletion(String id, String deletedAt, String peoSha256) {
        this.id = id; this.deletedAt = deletedAt; this.peoSha256 = peoSha256;
    }

    public String getId()        { return id; }
    /** ISO 8601. */
    public String getDeletedAt() { return deletedAt; }
    /** SHA-256 of the deleted Preservation Evidence Object — the digest that stays in the batch's hash tree. */
    public String getPeoSha256() { return peoSha256; }
}
