package com.sshteam.lib;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for {@link FilesystemDeviceStore} covering multi-server credential management
 * and default-server tracking.
 */
class FilesystemDeviceStoreTest {

    @TempDir
    Path tempDir;

    FilesystemDeviceStore store;

    static final String SERVER_A = "https://server-a.example.com";
    static final String SERVER_B = "https://server-b.example.com:8443";

    @BeforeEach
    void setUp() {
        store = new FilesystemDeviceStore(tempDir);
    }

    // ── toServerKey ───────────────────────────────────────────────────────────

    @Test
    void serverKeyStripsHttpsScheme() {
        assertThat(FilesystemDeviceStore.toServerKey("https://sshteam.example.com"))
            .isEqualTo("sshteam.example.com");
    }

    @Test
    void serverKeyStripsHttpScheme() {
        assertThat(FilesystemDeviceStore.toServerKey("http://localhost:8080"))
            .isEqualTo("localhost_8080");
    }

    @Test
    void serverKeyReplacesColonWithUnderscore() {
        assertThat(FilesystemDeviceStore.toServerKey("https://sshteam.example.com:8443"))
            .isEqualTo("sshteam.example.com_8443");
    }

    @Test
    void serverKeyStripsTrailingSlash() {
        assertThat(FilesystemDeviceStore.toServerKey("https://sshteam.example.com/"))
            .isEqualTo("sshteam.example.com");
    }

    @Test
    void serverKeyRejectsBlankUrl() {
        assertThatThrownBy(() -> FilesystemDeviceStore.toServerKey(""))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> FilesystemDeviceStore.toServerKey(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    // ── initServer ────────────────────────────────────────────────────────────

    @Test
    void initServerCreatesServerSubdirectory() throws Exception {
        store.initServer(SERVER_A);

        Path serverDir = store.serverDir(SERVER_A);
        assertThat(serverDir).isDirectory();
    }

    @Test
    void initServerIsIdempotent() throws Exception {
        store.initServer(SERVER_A);
        store.initServer(SERVER_A); // Should not throw
        assertThat(store.serverDir(SERVER_A)).isDirectory();
    }

    // ── saveCredentials / loadCredentials ─────────────────────────────────────

    @Test
    void saveThenLoadCredentialsRoundTrips() throws Exception {
        store.initServer(SERVER_A);
        long expiresAt = Instant.now().getEpochSecond() + 3600;
        DeviceCredentials saved = new DeviceCredentials(
            SERVER_A, "access-token-a", "refresh-token-a", expiresAt, "kid-a");

        store.saveCredentials(saved);
        Optional<DeviceCredentials> loaded = store.loadCredentials(SERVER_A);

        assertThat(loaded).isPresent();
        assertThat(loaded.get().serverUrl()).isEqualTo(SERVER_A);
        assertThat(loaded.get().accessToken()).isEqualTo("access-token-a");
        assertThat(loaded.get().refreshToken()).isEqualTo("refresh-token-a");
        assertThat(loaded.get().accessTokenExpiresAt()).isEqualTo(expiresAt);
        assertThat(loaded.get().keyId()).isEqualTo("kid-a");
    }

    @Test
    void loadCredentialsReturnsEmptyIfNotInitialized() throws Exception {
        assertThat(store.loadCredentials(SERVER_A)).isEmpty();
    }

    @Test
    void credentialsForTwoServersAreIndependent() throws Exception {
        store.initServer(SERVER_A);
        store.initServer(SERVER_B);

        long expiresAt = Instant.now().getEpochSecond() + 3600;
        store.saveCredentials(new DeviceCredentials(SERVER_A, "token-a", "refresh-a", expiresAt, "kid-a"));
        store.saveCredentials(new DeviceCredentials(SERVER_B, "token-b", "refresh-b", expiresAt, "kid-b"));

        DeviceCredentials credA = store.loadCredentials(SERVER_A).orElseThrow();
        DeviceCredentials credB = store.loadCredentials(SERVER_B).orElseThrow();

        assertThat(credA.accessToken()).isEqualTo("token-a");
        assertThat(credB.accessToken()).isEqualTo("token-b");
        assertThat(credA.keyId()).isEqualTo("kid-a");
        assertThat(credB.keyId()).isEqualTo("kid-b");
    }

    @Test
    void savedTokensAreEncryptedOnDisk() throws Exception {
        store.initServer(SERVER_A);
        long expiresAt = Instant.now().getEpochSecond() + 3600;
        store.saveCredentials(new DeviceCredentials(
            SERVER_A, "super-secret-token", "refresh-xyz", expiresAt, "kid-a"));

        // Read the raw config.json — tokens should not appear in plaintext
        Path configFile = store.serverDir(SERVER_A).resolve("config.json");
        String raw = Files.readString(configFile);
        assertThat(raw).doesNotContain("super-secret-token");
        assertThat(raw).doesNotContain("refresh-xyz");
    }

    // ── DPoP private key ──────────────────────────────────────────────────────

    @Test
    void saveThenLoadDpopPrivateKeyRoundTrips() throws Exception {
        store.initServer(SERVER_A);
        DpopSigner original = DpopSigner.generate();

        store.saveDpopPrivateKey(SERVER_A, original.toPrivateKeyJwkJson());
        String loaded = store.loadDpopPrivateKey(SERVER_A);
        DpopSigner restored = DpopSigner.fromPrivateKeyJwk(loaded);

        assertThat(restored.getKeyId()).isEqualTo(original.getKeyId());
    }

    @Test
    void dpopKeysForTwoServersAreStoredSeparately() throws Exception {
        store.initServer(SERVER_A);
        store.initServer(SERVER_B);

        DpopSigner signerA = DpopSigner.generate();
        DpopSigner signerB = DpopSigner.generate();

        store.saveDpopPrivateKey(SERVER_A, signerA.toPrivateKeyJwkJson());
        store.saveDpopPrivateKey(SERVER_B, signerB.toPrivateKeyJwkJson());

        assertThat(DpopSigner.fromPrivateKeyJwk(store.loadDpopPrivateKey(SERVER_A)).getKeyId())
            .isEqualTo(signerA.getKeyId());
        assertThat(DpopSigner.fromPrivateKeyJwk(store.loadDpopPrivateKey(SERVER_B)).getKeyId())
            .isEqualTo(signerB.getKeyId());
    }

    @Test
    void loadDpopPrivateKeyThrowsWhenMissing() {
        assertThatThrownBy(() -> store.loadDpopPrivateKey(SERVER_A))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("DPoP key not found");
    }

    // ── default server ────────────────────────────────────────────────────────

    @Test
    void getDefaultServerReturnsEmptyInitially() throws Exception {
        assertThat(store.getDefaultServer()).isEmpty();
    }

    @Test
    void setAndGetDefaultServer() throws Exception {
        store.initServer(SERVER_A);
        store.setDefaultServer(SERVER_A);

        assertThat(store.getDefaultServer()).contains(SERVER_A);
    }

    @Test
    void defaultServerCanBeOverridden() throws Exception {
        store.initServer(SERVER_A);
        store.initServer(SERVER_B);

        store.setDefaultServer(SERVER_A);
        assertThat(store.getDefaultServer()).contains(SERVER_A);

        store.setDefaultServer(SERVER_B);
        assertThat(store.getDefaultServer()).contains(SERVER_B);
    }

    // ── listServers ───────────────────────────────────────────────────────────

    @Test
    void listServersReturnsEmptyWhenNoneConfigured() throws Exception {
        assertThat(store.listServers()).isEmpty();
    }

    @Test
    void listServersReturnsBothServers() throws Exception {
        store.initServer(SERVER_A);
        store.initServer(SERVER_B);

        long expiresAt = Instant.now().getEpochSecond() + 3600;
        store.saveCredentials(new DeviceCredentials(SERVER_A, "tok-a", "ref-a", expiresAt, "kid-a"));
        store.saveCredentials(new DeviceCredentials(SERVER_B, "tok-b", "ref-b", expiresAt, "kid-b"));

        List<String> servers = store.listServers();
        assertThat(servers).containsExactlyInAnyOrder(SERVER_A, SERVER_B);
    }

    // ── resolveServer ─────────────────────────────────────────────────────────

    @Test
    void resolveServerReturnsExplicitServerWhenProvided() throws Exception {
        assertThat(store.resolveServer(SERVER_A)).isEqualTo(SERVER_A);
    }

    @Test
    void resolveServerFallsBackToDefault() throws Exception {
        store.initServer(SERVER_A);
        store.setDefaultServer(SERVER_A);

        assertThat(store.resolveServer(null)).isEqualTo(SERVER_A);
        assertThat(store.resolveServer("")).isEqualTo(SERVER_A);
    }

    @Test
    void resolveServerThrowsWhenNoDefaultAndNoExplicitServer() {
        assertThatThrownBy(() -> store.resolveServer(null))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("No server specified");
    }

    // ── loadDpopSigner convenience ────────────────────────────────────────────

    @Test
    void loadDpopSignerReturnsFunctionalSigner() throws Exception {
        store.initServer(SERVER_A);
        DpopSigner original = DpopSigner.generate();
        store.saveDpopPrivateKey(SERVER_A, original.toPrivateKeyJwkJson());

        DpopSigner loaded = store.loadDpopSigner(SERVER_A);
        assertThat(loaded.getKeyId()).isEqualTo(original.getKeyId());

        // Verify it can create a valid proof
        String proof = loaded.createProof("POST", "http://localhost/oauth2/token");
        assertThat(proof).isNotBlank();
    }

    // ── auto-default on first init (tested at store level) ────────────────────

    @Test
    void firstServerInitializedBecomesDefaultWhenNoDefaultSet() throws Exception {
        // Simulate what InitCommand does: if no default exists, set this server as default
        store.initServer(SERVER_A);

        boolean hasDefault = store.getDefaultServer().isPresent();
        if (!hasDefault) {
            store.setDefaultServer(SERVER_A);
        }

        assertThat(store.getDefaultServer()).contains(SERVER_A);
    }

    @Test
    void secondServerDoesNotOverrideExistingDefault() throws Exception {
        // SERVER_A is first, becomes default
        store.initServer(SERVER_A);
        store.setDefaultServer(SERVER_A);

        // SERVER_B is second — without --default flag, default should not change
        store.initServer(SERVER_B);
        boolean hasDefault = store.getDefaultServer().isPresent();
        // hasDefault is true so we do NOT call setDefaultServer again
        assertThat(hasDefault).isTrue();

        assertThat(store.getDefaultServer()).contains(SERVER_A);
    }
}
