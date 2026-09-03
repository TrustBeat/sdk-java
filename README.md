# TrustBeat Java SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

Part of **[TrustBeat](https://trustbeat.eu)** — digital trust infrastructure for the EU.
All SDKs (Python, TypeScript, Java, C#, Go): **[trustbeat.eu/sdks](https://trustbeat.eu/sdks)**.

## Install

**Maven:**
```xml
<dependency>
    <groupId>eu.trustbeat</groupId>
    <artifactId>trustbeat-sdk</artifactId>
    <version>0.2.0</version>
</dependency>
```

**Gradle:**
```gradle
implementation 'eu.trustbeat:trustbeat-sdk:0.2.0'
```

## Quickstart

```java
import eu.trustbeat.sdk.TrustBeat;
import eu.trustbeat.sdk.AnchorJob;
import eu.trustbeat.sdk.AnchorProof;

TrustBeat tb = new TrustBeat.Builder().apiKey("tb_live_...").build();

// Anchor a file (SHA-256 computed locally, file never leaves your machine).
// anchorFileWait() blocks until the proof is ready (next batch, up to 11 min).
AnchorProof proof = tb.anchorFileWait(Path.of("contract.pdf"));
System.out.println(proof.getId());          // tracking ID
System.out.println(proof.getAnchoredAt());  // ISO 8601 timestamp
System.out.println(proof.getMerkleRoot());  // Merkle root of the batch

// Verify locally — no network call
boolean valid = tb.verify(proof);

// Or anchor a raw SHA-256 hash without blocking, then wait for the proof.
AnchorJob job = tb.anchor("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
AnchorProof waited = tb.anchorWait(job.getId());  // polls up to 11 min

```

## Tamper-Evident Logs (NIS2)

Anchor a log hash together with canonical metadata for NIS2 Article 21 audit trails.
The server seals the metadata into the Merkle leaf, so the proof covers both the log
content and its context.

```java
import eu.trustbeat.sdk.*;
import java.nio.file.Path;

TrustBeat tb = new TrustBeat.Builder().apiKey("tb_live_...").build();

// Hash the log yourself — content never leaves your machine.
String logHash = TrustBeat.hashFile(Path.of("app.log"));

LogMetadata meta = new LogMetadata.Builder()
    .logSource(new LogSource.Builder().uri("/var/log/app.log").name("Application log").build())
    .sourceIdentity(new LogSourceIdentity.Builder().hostname("web-01").serviceName("payments").build())
    .timeEnvelope(new LogTimeEnvelope("2026-04-15T00:00:00Z", "2026-04-15T23:59:59Z"))
    .build();

LogAnchorJob job = tb.anchorLog(logHash, meta, "incident-2026-05");
System.out.println(job.getId() + " " + job.getCombinedHash());

// Wait for the qualified anchor (next batch, up to ~11 min).
LogProof proof = tb.anchorLogWait(job.getId());
System.out.println(proof.getVerificationStatus()); // "VERIFIED"
```

## Webhooks

If your account has a webhook secret configured, every delivery is signed with
an `X-TrustBeat-Signature` header. Verify it with the raw request body —
before any JSON parsing:

```java
boolean ok = TrustBeat.verifyWebhookSignature(rawBody, signatureHeader, webhookSecret);
if (!ok) throw new SecurityException("Invalid webhook signature");
```

Rejects replays older than 5 minutes by default; see `WebhookVerifier` for the
overload with explicit tolerance.

Portable proof bundles for offline verification: `exportAiDecision(id)`,
`exportVerification(id)`, `exportLog(id)` — each returns raw JSON bundle bytes.

## Requirements

- Java 11+
- Zero runtime dependencies (java.net.http, java.security from stdlib)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)


### Merkle algorithm

Every proof declares how it must be folded, in `proof.getMerkleAlgorithm()`:

| Value | Construction |
|---|---|
| `trustbeat-legacy-sha256` | leaf = your hash, parent = `SHA-256(left \|\| right)` |
| `rfc6962-sha256` | leaf = `SHA-256(0x00 \|\| hash)`, parent = `SHA-256(0x01 \|\| left \|\| right)` |

`verify` dispatches on it for you. A proof with no label was issued before the
field existed and is legacy. An algorithm this SDK version does not implement
throws `UnsupportedAlgorithmException` rather than returning `false` — "cannot
check" is not "invalid".
