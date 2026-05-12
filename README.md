# TrustBeat Java SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

## Install

**Maven:**
```xml
<dependency>
    <groupId>eu.trustbeat</groupId>
    <artifactId>trustbeat-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

**Gradle:**
```gradle
implementation 'eu.trustbeat:trustbeat-sdk:0.1.0'
```

## Quickstart

```java
import eu.trustbeat.TrustBeat;
import eu.trustbeat.model.AnchorProof;

TrustBeat tb = new TrustBeat("tb_live_...");

// Anchor a file (SHA-256 computed locally, file never leaves your machine)
AnchorProof proof = tb.anchorFile(Path.of("contract.pdf"));
System.out.println(proof.getId());          // tracking ID
System.out.println(proof.getAnchoredAt());  // ISO 8601 timestamp
System.out.println(proof.getMerkleRoot());  // Merkle root of the batch

// Verify locally — no network call
boolean valid = tb.verify(proof);

// Anchor a raw SHA-256 hash
AnchorJob job = tb.anchor("e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855");
AnchorProof waited = tb.anchorWait(job.getId());  // polls up to 11 min

```

## Requirements

- Java 11+
- Zero runtime dependencies (java.net.http, java.security from stdlib)

## Documentation

Full API reference and guides at [trustbeat.eu/docs](https://trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)
