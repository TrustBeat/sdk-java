# Releasing the Java SDK to Maven Central

The `pom.xml` ships a `release` profile that builds the `-sources.jar` and
`-javadoc.jar`, GPG-signs every artifact, and uploads the bundle to the
[Maven Central Portal](https://central.sonatype.com). It is **inactive by
default**, so day-to-day `mvn test` / `mvn package` stay fast and need no key.

Coordinates: `eu.trustbeat:trustbeat-sdk`.

---

## One-time setup

### 1. Verify the `eu.trustbeat` namespace

On <https://central.sonatype.com> → **Namespaces** → add `eu.trustbeat`. Because
the namespace matches a domain we own, verification is a DNS **TXT** record on
`trustbeat.eu` containing the verification code the Portal shows. Add it at the
registrar (vedos.cz), then click *Verify*. One-time; never repeated.

### 2. Create a GPG signing key

```bash
gpg --gen-key                       # use the Trustbeat release identity / email
gpg --list-secret-keys --keyid-format=long
# Publish the public key so Central can verify the signatures:
gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
```

Keep the private key and its passphrase safe — they go into CI secrets (below).

### 3. Generate a Central Portal token

Portal → **Account** → **Generate User Token**. You get a username/password pair
(it is *not* your login). Put it in `~/.m2/settings.xml` under the server id the
profile expects (`central`):

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>TOKEN_USERNAME</username>
      <password>TOKEN_PASSWORD</password>
    </server>
  </servers>
</settings>
```

---

## Cutting a release (local)

```bash
cd sdk/java
# version in pom.xml is the release version (e.g. 0.1.0 — no -SNAPSHOT)
MAVEN_GPG_PASSPHRASE='<your-gpg-passphrase>' \
  mvn -P release clean deploy
```

What happens:

1. `clean test` — unit tests run.
2. `package` — main jar (Smoke runner excluded), `-sources.jar` (Smoke.java
   excluded), `-javadoc.jar`.
3. `verify` — `maven-gpg-plugin` signs all artifacts (`.asc`).
4. `deploy` — `central-publishing-maven-plugin` uploads the bundle and, with
   `autoPublish=true` + `waitUntil=published`, releases it. The command blocks
   until Central reports the version as published (a few minutes).

Then tag the mirrored repo:

```bash
git tag v0.1.0 && git push origin v0.1.0   # on TrustBeat/sdk-java
```

> First publish to a fresh namespace can take up to a few hours to appear on
> search.maven.org even after the Portal says "published". Resolving the
> dependency works as soon as it is published.

---

## CI (GitHub Actions, optional)

Run the same command in `TrustBeat/sdk-java` on tag push, with secrets:

| Secret | Value |
|---|---|
| `CENTRAL_TOKEN_USERNAME` / `CENTRAL_TOKEN_PASSWORD` | Portal user token |
| `GPG_PRIVATE_KEY` | ASCII-armored private key (`gpg --armor --export-secret-keys`) |
| `MAVEN_GPG_PASSPHRASE` | key passphrase |

Sketch:

```yaml
- uses: actions/setup-java@<pinned-sha>   # temurin 17, server-id: central
  with:
    java-version: '17'
    distribution: temurin
    server-id: central
    server-username: CENTRAL_TOKEN_USERNAME
    server-password: CENTRAL_TOKEN_PASSWORD
    gpg-private-key: ${{ secrets.GPG_PRIVATE_KEY }}
    gpg-passphrase: MAVEN_GPG_PASSPHRASE
- run: mvn -P release -B clean deploy
  env:
    MAVEN_GPG_PASSPHRASE: ${{ secrets.MAVEN_GPG_PASSPHRASE }}
```

Pin the action to a commit SHA per the repo's CI-security rule.

---

## Bumping the version

Edit `<version>` in `pom.xml` (Central rejects re-publishing an existing
version). Use `X.Y.Z` for releases; append `-SNAPSHOT` only for local iteration —
snapshots are **not** accepted by the Central Portal.
