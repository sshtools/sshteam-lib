package com.sshteam.lib;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.jadaptive.hsm.encrypt.HsmEncryptionProvider;
import com.jadaptive.hsm.encrypt.SoftwareEncryptionProvider;

/**
 * {@link DeviceStore} implementation backed by the local filesystem.
 *
 * <p>Layout under {@code baseDir} (default: {@code ~/.sshteam}):
 * <pre>
 *   ~/.sshteam/
 *     defaults.json             – {"defaultServer": "https://..."}
 *     &lt;serverKey&gt;/
 *       config.json             – device credentials (tokens encrypted at rest)
 *       dpop-key.enc            – AES-encrypted DPoP private key JWK
 *       sshteam-hsm.p12         – HSM keystore for this server
 * </pre>
 * </p>
 *
 * <p>The {@code serverKey} is derived from the server URL by stripping the scheme and
 * replacing {@code :} and {@code /} with {@code _}, e.g.
 * {@code https://sshteam.example.com:8443} → {@code sshteam.example.com_8443}.</p>
 */
public class FilesystemDeviceStore implements DeviceStore {

    private static final String DEFAULTS_FILE = "defaults.json";
    private static final String CONFIG_FILE = "config.json";
    private static final String DPOP_KEY_FILE = "dpop-key.enc";
    private static final String HSM_KEYSTORE_FILE = "sshteam-hsm.p12";
    private static final String HSM_ALIAS = "sshteam-cli";
    private static final String HSM_PASSWORD = "changeit-changeit";
    private static final String ENC_PREFIX = "enc::";

    private final Path baseDir;
    private final ObjectMapper mapper;

    public FilesystemDeviceStore(Path baseDir) {
        this.baseDir = baseDir;
        this.mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    /** Returns a store rooted at {@code ~/.sshteam}. */
    public static FilesystemDeviceStore defaultStore() {
        return new FilesystemDeviceStore(
            Path.of(System.getProperty("user.home"), ".sshteam"));
    }

    @Override
    public void initServer(String serverUrl) throws IOException {
        ensureBaseDirExists();
        Path dir = serverDir(serverUrl);
        if (!Files.exists(dir)) {
            try {
                Files.createDirectories(dir,
                    PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rwx------")));
            } catch (UnsupportedOperationException ex) {
                Files.createDirectories(dir);
            }
        }
    }

    @Override
    public void saveCredentials(DeviceCredentials credentials) throws Exception {
        StoredCredentials stored = new StoredCredentials(
            credentials.serverUrl(),
            encryptToken(credentials.serverUrl(), credentials.accessToken()),
            encryptToken(credentials.serverUrl(), credentials.refreshToken()),
            credentials.accessTokenExpiresAt(),
            credentials.keyId()
        );
        Path file = serverDir(credentials.serverUrl()).resolve(CONFIG_FILE);
        mapper.writeValue(file.toFile(), stored);
        restrictPermissions(file);
    }

    @Override
    public Optional<DeviceCredentials> loadCredentials(String serverUrl) throws Exception {
        Path file = serverDir(serverUrl).resolve(CONFIG_FILE);
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        StoredCredentials stored = mapper.readValue(file.toFile(), StoredCredentials.class);
        return Optional.of(new DeviceCredentials(
            stored.serverUrl(),
            decryptToken(serverUrl, stored.accessToken()),
            decryptToken(serverUrl, stored.refreshToken()),
            stored.accessTokenExpiresAt(),
            stored.keyId()
        ));
    }

    @Override
    public void saveDpopPrivateKey(String serverUrl, String privateKeyJwk) throws Exception {
        HsmEncryptionProvider hsm = buildHsm(serverUrl);
        String encrypted = hsm.encrypt(privateKeyJwk);
        Path file = serverDir(serverUrl).resolve(DPOP_KEY_FILE);
        Files.writeString(file, encrypted, StandardCharsets.UTF_8);
        restrictPermissions(file);
    }

    @Override
    public String loadDpopPrivateKey(String serverUrl) throws Exception {
        Path file = serverDir(serverUrl).resolve(DPOP_KEY_FILE);
        if (!Files.exists(file)) {
            throw new IllegalStateException(
                "DPoP key not found for " + serverUrl +
                " — run 'sshteam init " + serverUrl + "' first");
        }
        String encrypted = Files.readString(file, StandardCharsets.UTF_8);
        return buildHsm(serverUrl).decrypt(encrypted);
    }

    @Override
    public void setDefaultServer(String serverUrl) throws IOException {
        ensureBaseDirExists();
        Path file = baseDir.resolve(DEFAULTS_FILE);
        mapper.writeValue(file.toFile(), new DefaultsRecord(serverUrl));
        restrictPermissions(file);
    }

    @Override
    public Optional<String> getDefaultServer() throws IOException {
        Path file = baseDir.resolve(DEFAULTS_FILE);
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        DefaultsRecord rec = mapper.readValue(file.toFile(), DefaultsRecord.class);
        return Optional.ofNullable(rec.defaultServer())
            .filter(s -> !s.isBlank());
    }

    @Override
    public List<String> listServers() throws IOException {
        if (!Files.exists(baseDir)) {
            return List.of();
        }
        List<String> servers = new ArrayList<>();
        try (Stream<Path> stream = Files.list(baseDir)) {
            stream.filter(Files::isDirectory).forEach(dir -> {
                Path config = dir.resolve(CONFIG_FILE);
                if (Files.exists(config)) {
                    try {
                        StoredCredentials stored = mapper.readValue(config.toFile(), StoredCredentials.class);
                        if (stored.serverUrl() != null && !stored.serverUrl().isBlank()) {
                            servers.add(stored.serverUrl());
                        }
                    } catch (IOException ignored) {
                        // Skip malformed entries
                    }
                }
            });
        }
        return List.copyOf(servers);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Returns the per-server subdirectory for the given server URL. */
    Path serverDir(String serverUrl) {
        return baseDir.resolve(toServerKey(serverUrl));
    }

    /**
     * Converts a server URL to a safe filesystem directory name.
     *
     * <p>Examples:
     * <ul>
     *   <li>{@code https://sshteam.example.com} → {@code sshteam.example.com}</li>
     *   <li>{@code https://sshteam.example.com:8443} → {@code sshteam.example.com_8443}</li>
     * </ul>
     * </p>
     */
    public static String toServerKey(String serverUrl) {
        if (serverUrl == null || serverUrl.isBlank()) {
            throw new IllegalArgumentException("Server URL cannot be blank");
        }
        String s = serverUrl;
        if (s.startsWith("https://")) s = s.substring(8);
        else if (s.startsWith("http://")) s = s.substring(7);
        // Strip trailing slashes
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        // Replace path/port separators with underscores
        s = s.replace(':', '_').replace('/', '_');
        return s;
    }

    private void ensureBaseDirExists() throws IOException {
        if (!Files.exists(baseDir)) {
            try {
                Files.createDirectories(baseDir,
                    PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rwx------")));
            } catch (UnsupportedOperationException ex) {
                Files.createDirectories(baseDir);
            }
        }
    }

    private HsmEncryptionProvider buildHsm(String serverUrl) throws Exception {
        Path serverDirectory = serverDir(serverUrl);
        HsmEncryptionProvider provider = SoftwareEncryptionProvider.builder()
            .setEnabled(true)
            .setKeystoreDir(serverDirectory.toString())
            .setKeystoreSubdir("")
            .setKeystoreFilename(HSM_KEYSTORE_FILE)
            .setKeystoreAlias(HSM_ALIAS)
            .setKeystorePassword(HSM_PASSWORD)
            .build();
        provider.init();
        return provider;
    }

    private String encryptToken(String serverUrl, String token) {
        if (token == null || token.isBlank()) {
            return token;
        }
        try {
            return ENC_PREFIX + buildHsm(serverUrl).encrypt(token);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to encrypt token", ex);
        }
    }

    private String decryptToken(String serverUrl, String token) {
        if (token == null || token.isBlank()) {
            return token;
        }
        // Legacy / plain-text fallback
        if (!token.startsWith(ENC_PREFIX)) {
            return token;
        }
        try {
            return buildHsm(serverUrl).decrypt(token.substring(ENC_PREFIX.length()));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to decrypt token", ex);
        }
    }

    private static void restrictPermissions(Path file) {
        try {
            Files.setPosixFilePermissions(file,
                Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Best effort on non-POSIX file systems (Windows)
        }
    }

    // ── JSON serialisation classes ────────────────────────────────────────────

    /** Internal class for {@code config.json} (tokens stored encrypted). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class StoredCredentials {
        @JsonProperty String serverUrl;
        @JsonProperty String accessToken;
        @JsonProperty String refreshToken;
        @JsonProperty long accessTokenExpiresAt;
        @JsonProperty String keyId;

        StoredCredentials() {}

        StoredCredentials(String serverUrl, String accessToken, String refreshToken,
                          long accessTokenExpiresAt, String keyId) {
            this.serverUrl = serverUrl;
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.accessTokenExpiresAt = accessTokenExpiresAt;
            this.keyId = keyId;
        }

        String serverUrl() { return serverUrl; }
        String accessToken() { return accessToken; }
        String refreshToken() { return refreshToken; }
        long accessTokenExpiresAt() { return accessTokenExpiresAt; }
        String keyId() { return keyId; }
    }

    /** Class for {@code defaults.json}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class DefaultsRecord {
        @JsonProperty String defaultServer;

        DefaultsRecord() {}

        DefaultsRecord(String defaultServer) {
            this.defaultServer = defaultServer;
        }

        String defaultServer() { return defaultServer; }
    }
}
