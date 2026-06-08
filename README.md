# sshteam-lib

[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/com.sshteam/sshteam-lib)](https://central.sonatype.com/artifact/com.sshteam/sshteam-lib)

Core Java library for the **SSH Teams** ecosystem. Provides:

- **`DpopSigner`** — generate and sign [DPoP proof JWTs](https://datatracker.ietf.org/doc/html/rfc9449) (EC P-256)
- **`SshteamHttpClient`** — thin HTTP client for the SSH Teams server API (OAuth2 device flow, token refresh, SSH certificate signing, device revocation)
- **`DeviceStore` / `FilesystemDeviceStore`** — encrypted credential storage, multi-server support
- **`DeviceCredentials`** — value type carrying access/refresh tokens and DPoP key material

---

## Requirements

| Requirement | Version |
|---|---|
| Java | 11+ |
| Maven | 3.8+ |

---

## Installation

### Maven

```xml
<dependency>
    <groupId>com.sshteam</groupId>
    <artifactId>sshteam-lib</artifactId>
    <version>0.0.1</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.sshteam:sshteam-lib:0.0.1'
```

---

## API Overview

| Class | Role |
|---|---|
| [`DpopSigner`](#dpopsigner) | Generates EC P-256 key pairs and creates RFC 9449 DPoP proof JWTs |
| [`SshteamHttpClient`](#sshteamhttpclient) | Calls SSH Teams server REST/OAuth2 endpoints |
| [`DeviceStore`](#devicestore) | Interface for multi-server credential storage |
| [`FilesystemDeviceStore`](#filesystemdevicestore) | Default implementation — stores credentials under `~/.sshteam/` |
| [`DeviceCredentials`](#devicecredentials) | Immutable value type holding tokens and key metadata |

---

## API Usage

### DpopSigner

`DpopSigner` creates RFC 9449-compliant DPoP proof JWTs signed with an EC P-256 key pair. Proofs must be generated fresh for every HTTP request.

#### Generate a new key pair

```java
DpopSigner signer = DpopSigner.generate();

// Retrieve the key ID embedded in the JWK (use as the DPoP key identifier)
String kid = signer.getKeyId();
```

#### Restore from a persisted private key

```java
// fullJwkJson is the JSON produced by toPrivateKeyJwkJson() and
// decrypted from the DeviceStore
DpopSigner signer = DpopSigner.fromPrivateKeyJwk(fullJwkJson);
```

#### Create a DPoP proof for a token endpoint (no access token)

```java
// Used when calling the OAuth2 token endpoint without a bound access token
String proof = signer.createProof("POST", "https://sshteam.example.com/oauth2/token");
```

#### Create a DPoP proof for a resource request (with access token)

```java
// The access token hash (ath) is computed automatically per RFC 9449 §4.2
String proof = signer.createProof(
    "POST",
    "https://sshteam.example.com/api/v1/ssh/sign",
    accessToken
);
```

#### Serialise the key pair for encrypted storage

```java
// Public JWK — safe to transmit to the server during registration
String publicJwk  = signer.toPublicKeyJwkJson();

// Full JWK including the private key — MUST be encrypted before persisting
String privateJwk = signer.toPrivateKeyJwkJson();
```

---

### SshteamHttpClient

A thin, zero-dependency HTTP client (Java 11 `HttpClient`) for the SSH Teams server API.

#### Construct the client

```java
SshteamHttpClient client = new SshteamHttpClient("https://sshteam.example.com");
```

The trailing slash is stripped automatically if present.

#### OAuth2 device authorisation — initiate flow

```java
JsonNode response = client.deviceAuthorize("sshteam-cli", "signing");

String deviceCode      = response.get("device_code").asText();
String verificationUri = response.get("verification_uri").asText();
int    interval        = response.get("interval").asInt(5);
```

#### OAuth2 device authorisation — poll for token

```java
String dpopProof = signer.createProof("POST", client.tokenEndpointUrl());

JsonNode tokenResponse = client.pollToken("sshteam-cli", deviceCode, dpopProof);

if (tokenResponse.has("error")) {
    String error = tokenResponse.get("error").asText();
    // "authorization_pending" — keep polling; "slow_down" — increase interval
} else {
    String accessToken  = tokenResponse.get("access_token").asText();
    String refreshToken = tokenResponse.get("refresh_token").asText();
    long   expiresIn    = tokenResponse.get("expires_in").asLong();
}
```

#### Refresh an access token

```java
String dpopProof = signer.createProof("POST", client.tokenEndpointUrl());

JsonNode refreshed = client.refreshToken(storedRefreshToken, dpopProof);
String newAccessToken = refreshed.get("access_token").asText();
```

Throws `SshteamHttpClient.SshteamApiException` on HTTP 4xx/5xx.

#### Request an SSH certificate

```java
String dpopProof = signer.createProof("POST", client.signEndpointUrl(), accessToken);

JsonNode result = client.sign(
    accessToken,
    dpopProof,
    sshPublicKey,      // OpenSSH format, e.g. "ssh-ed25519 AAAA..."
    "alice",           // target UNIX principal
    serverFingerprint, // SSH host key fingerprint
    "Europe/London",   // IANA timezone — pass null to omit
    "ED25519"          // certificate type: "ED25519" or "RSA"
);

String certificate = result.get("certificate").asText();
```

#### Revoke a registered device

```java
String dpopProof = signer.createProof("DELETE", client.revokeDeviceUrl(deviceId), accessToken);

int statusCode = client.revokeDevice(deviceId, accessToken, dpopProof);
// 204 → revoked; 404 → device not found
```

#### Endpoint URL helpers

```java
client.tokenEndpointUrl();          // https://host/oauth2/token
client.signEndpointUrl();           // https://host/api/v1/ssh/sign
client.revokeDeviceUrl("device-1"); // https://host/api/v1/devices/device-1
client.getServerUrl();              // base URL used at construction
```

---

### DeviceStore

`DeviceStore` is an interface for multi-server credential storage. All sensitive values (tokens, private key JWK) are encrypted at rest by the implementation.

```java
public interface DeviceStore {
    void initServer(String serverUrl) throws IOException;
    void saveCredentials(DeviceCredentials credentials) throws Exception;
    Optional<DeviceCredentials> loadCredentials(String serverUrl) throws Exception;
    void saveDpopPrivateKey(String serverUrl, String privateKeyJwk) throws Exception;
    String loadDpopPrivateKey(String serverUrl) throws Exception;
    void setDefaultServer(String serverUrl) throws IOException;
    Optional<String> getDefaultServer() throws IOException;
    List<String> listServers() throws IOException;

    // Convenience defaults built on the above primitives:
    default String resolveServer(String serverUrl) throws IOException { ... }
    default DpopSigner loadDpopSigner(String serverUrl) throws Exception { ... }
    default String getCurrentAccessToken(String serverUrl, DpopSigner signer) throws Exception { ... }
}
```

#### `resolveServer(String serverUrl)`

Returns `serverUrl` if non-blank, otherwise returns the stored default server URL. Throws `IllegalStateException` if neither is set.

#### `loadDpopSigner(String serverUrl)`

Loads the encrypted private key for `serverUrl` and constructs a `DpopSigner` from it. Equivalent to `DpopSigner.fromPrivateKeyJwk(store.loadDpopPrivateKey(serverUrl))`.

#### `getCurrentAccessToken(String serverUrl, DpopSigner signer)`

Returns a valid access token for `serverUrl`. If the stored token is within 60 seconds of expiry and a refresh token is available, the token is refreshed automatically, persisted, and the new value is returned. Throws `IllegalStateException` if no credentials are stored or if the token has expired with no refresh token.

---

### FilesystemDeviceStore

The standard `DeviceStore` implementation. Stores all state under a configurable base directory (default: `~/.sshteam/`). Tokens and the DPoP private key JWK are AES-encrypted at rest using a per-server software HSM keystore.

#### Directory layout

```
~/.sshteam/
  defaults.json                  – {"defaultServer": "https://..."}
  <serverKey>/
    config.json                  – encrypted access/refresh tokens + key metadata
    dpop-key.enc                 – AES-encrypted DPoP private key JWK
    sshteam-hsm.p12              – PKCS#12 keystore used for encryption/decryption
```

The `<serverKey>` is derived from the server URL by stripping the scheme and replacing `:` and `/` with `_`:

| Server URL | Directory name |
|---|---|
| `https://sshteam.example.com` | `sshteam.example.com` |
| `https://sshteam.example.com:8443` | `sshteam.example.com_8443` |

#### Construction

```java
// Default store at ~/.sshteam
FilesystemDeviceStore store = FilesystemDeviceStore.defaultStore();

// Custom base directory (e.g. for testing)
FilesystemDeviceStore store = new FilesystemDeviceStore(Path.of("/tmp/test-store"));
```

#### Full registration workflow example

```java
String serverUrl = "https://sshteam.example.com";
FilesystemDeviceStore store = FilesystemDeviceStore.defaultStore();

// 1. Initialise storage for this server
store.initServer(serverUrl);

// 2. Generate a fresh DPoP key pair and persist it
DpopSigner signer = DpopSigner.generate();
store.saveDpopPrivateKey(serverUrl, signer.toPrivateKeyJwkJson());

// 3. Run the OAuth2 device flow
SshteamHttpClient client = new SshteamHttpClient(serverUrl);
JsonNode authResponse = client.deviceAuthorize("sshteam-cli", "signing");
String deviceCode = authResponse.get("device_code").asText();
System.out.println("Visit: " + authResponse.get("verification_uri_complete").asText());

// 4. Poll until the user authorises
JsonNode tokenResponse = null;
while (true) {
    Thread.sleep(5_000);
    String proof = signer.createProof("POST", client.tokenEndpointUrl());
    tokenResponse = client.pollToken("sshteam-cli", deviceCode, proof);
    if (!tokenResponse.has("error")) break;
    if (!"authorization_pending".equals(tokenResponse.get("error").asText())) {
        throw new RuntimeException("Device flow failed: " + tokenResponse);
    }
}

// 5. Persist the obtained credentials
long now = Instant.now().getEpochSecond();
store.saveCredentials(new DeviceCredentials(
    serverUrl,
    tokenResponse.get("access_token").asText(),
    tokenResponse.get("refresh_token").asText(),
    now + tokenResponse.get("expires_in").asLong(),
    signer.getKeyId()
));

// 6. (Optional) make this the default server
store.setDefaultServer(serverUrl);
```

#### SSH certificate request example

```java
FilesystemDeviceStore store = FilesystemDeviceStore.defaultStore();
String serverUrl = store.resolveServer(null);   // uses the stored default
DpopSigner signer = store.loadDpopSigner(serverUrl);
SshteamHttpClient client = new SshteamHttpClient(serverUrl);

String accessToken = store.getCurrentAccessToken(serverUrl, signer);
String dpopProof   = signer.createProof("POST", client.signEndpointUrl(), accessToken);

JsonNode result = client.sign(
    accessToken,
    dpopProof,
    Files.readString(Path.of(System.getProperty("user.home"), ".ssh", "id_ed25519.pub")).trim(),
    System.getProperty("user.name"),
    serverFingerprint,
    ZoneId.systemDefault().getId(),
    "ED25519"
);

System.out.println(result.get("certificate").asText());
```

---

### DeviceCredentials

Immutable value type carrying all credential data for one server.

```java
DeviceCredentials creds = store.loadCredentials(serverUrl).orElseThrow();

creds.serverUrl();              // "https://sshteam.example.com"
creds.accessToken();            // DPoP-bound access token (plain-text in memory)
creds.refreshToken();           // refresh token (may be null)
creds.accessTokenExpiresAt();   // Unix epoch seconds
creds.keyId();                  // DPoP JWK key ID (kid)
```

Construct directly when saving:

```java
DeviceCredentials creds = new DeviceCredentials(
    serverUrl,
    accessToken,
    refreshToken,
    Instant.now().getEpochSecond() + expiresIn,
    signer.getKeyId()
);
store.saveCredentials(creds);
```

---

## Publishing to Maven Central

The project uses the [Sonatype Central Portal publisher plugin](https://central.sonatype.org/publish/publish-portal-maven/). Publishing requires a GPG key and valid Central Portal credentials.

### Set up credentials

Add the following to `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username><!-- Central Portal username token --></username>
      <password><!-- Central Portal password token --></password>
    </server>
  </servers>
</settings>
```

### Deploy a release

```bash
# Build, sign, and upload to the Central Portal staging area
mvn clean deploy -Prelease

# The plugin waits until the bundle is validated, then you can
# promote it to release from https://central.sonatype.com/publishing
```

### Deploy a snapshot

```bash
# No GPG signing required for snapshots
mvn clean deploy
```

Snapshots are published to `https://central.sonatype.com/repository/maven-snapshots/` and can be consumed immediately by adding that repository to your project.

---

## Building locally

```bash
mvn clean install
```

Run tests only:

```bash
mvn test
```

---

## License

Copyright SSH Teams contributors.  
Licensed under the [Apache License, Version 2.0](LICENSE).
