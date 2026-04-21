package eu.trustbeat.sdk;

import java.util.List;

/** Result of {@link TrustBeat#validateCertificate(byte[])}. */
public final class CertificateValidationResult {
    private final String       subject;
    private final String       issuer;
    private final String       serial;
    private final String       notBefore;
    private final String       notAfter;
    private final boolean      qualified;
    private final boolean      onEutl;
    private final boolean      qscd;
    private final String       revocationStatus;
    private final String       revocationTime;
    private final List<String> keyUsage;
    private final boolean      valid;
    private final String       validatedAt;

    public CertificateValidationResult(String subject, String issuer, String serial,
                                        String notBefore, String notAfter,
                                        boolean qualified, boolean onEutl, boolean qscd,
                                        String revocationStatus, String revocationTime,
                                        List<String> keyUsage, boolean valid, String validatedAt) {
        this.subject          = subject;
        this.issuer           = issuer;
        this.serial           = serial;
        this.notBefore        = notBefore;
        this.notAfter         = notAfter;
        this.qualified        = qualified;
        this.onEutl           = onEutl;
        this.qscd             = qscd;
        this.revocationStatus = revocationStatus;
        this.revocationTime   = revocationTime;
        this.keyUsage         = keyUsage;
        this.valid            = valid;
        this.validatedAt      = validatedAt;
    }

    public String       getSubject()          { return subject; }
    public String       getIssuer()           { return issuer; }
    public String       getSerial()           { return serial; }
    public String       getNotBefore()        { return notBefore; }
    public String       getNotAfter()         { return notAfter; }
    public boolean      isQualified()         { return qualified; }
    public boolean      isOnEutl()            { return onEutl; }
    public boolean      isQscd()              { return qscd; }
    public String       getRevocationStatus() { return revocationStatus; }
    public String       getRevocationTime()   { return revocationTime; }
    public List<String> getKeyUsage()         { return keyUsage; }
    public boolean      isValid()             { return valid; }
    public String       getValidatedAt()      { return validatedAt; }
}
