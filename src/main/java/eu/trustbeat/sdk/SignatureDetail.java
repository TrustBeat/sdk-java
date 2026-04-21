package eu.trustbeat.sdk;

/** Per-signature result within a {@link VerificationReport}. */
public final class SignatureDetail {
    private final int     index;
    private final String  signerName;
    private final String  signerEmail;
    private final String  signingTime;
    private final String  certSerial;
    private final String  certFingerprint;
    private final String  certIssuer;
    private final boolean qualified;
    private final boolean onEutl;
    private final boolean qscd;
    private final String  revocationStatus;
    private final String  revocationTime;
    private final String  ocspResponse;
    private final String  signatureLevel;
    private final boolean timestampPresent;
    private final String  timestampSerial;
    private final String  verdict;

    public SignatureDetail(int index, String signerName, String signerEmail,
                           String signingTime, String certSerial, String certFingerprint,
                           String certIssuer, boolean qualified, boolean onEutl, boolean qscd,
                           String revocationStatus, String revocationTime, String ocspResponse,
                           String signatureLevel, boolean timestampPresent, String timestampSerial,
                           String verdict) {
        this.index            = index;
        this.signerName       = signerName;
        this.signerEmail      = signerEmail;
        this.signingTime      = signingTime;
        this.certSerial       = certSerial;
        this.certFingerprint  = certFingerprint;
        this.certIssuer       = certIssuer;
        this.qualified        = qualified;
        this.onEutl           = onEutl;
        this.qscd             = qscd;
        this.revocationStatus = revocationStatus;
        this.revocationTime   = revocationTime;
        this.ocspResponse     = ocspResponse;
        this.signatureLevel   = signatureLevel;
        this.timestampPresent = timestampPresent;
        this.timestampSerial  = timestampSerial;
        this.verdict          = verdict;
    }

    public int     getIndex()            { return index; }
    public String  getSignerName()       { return signerName; }
    public String  getSignerEmail()      { return signerEmail; }
    public String  getSigningTime()      { return signingTime; }
    public String  getCertSerial()       { return certSerial; }
    public String  getCertFingerprint()  { return certFingerprint; }
    public String  getCertIssuer()       { return certIssuer; }
    public boolean isQualified()         { return qualified; }
    public boolean isOnEutl()            { return onEutl; }
    public boolean isQscd()              { return qscd; }
    public String  getRevocationStatus() { return revocationStatus; }
    public String  getRevocationTime()   { return revocationTime; }
    public String  getOcspResponse()     { return ocspResponse; }
    public String  getSignatureLevel()   { return signatureLevel; }
    public boolean isTimestampPresent()  { return timestampPresent; }
    public String  getTimestampSerial()  { return timestampSerial; }
    public String  getVerdict()          { return verdict; }
}
