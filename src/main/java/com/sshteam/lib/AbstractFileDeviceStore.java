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

/**
 * Reusable file-backed {@link DeviceStore} base implementation.
 *
 * <p>This class centralizes server directory layout, JSON persistence, and token
 * prefix compatibility behavior. Implementations choose the storage root path and
 * provide encryption strategy through {@link DeviceStoreEncryption}.</p>
 */
public abstract class AbstractFileDeviceStore implements DeviceStore {

    protected static final String DEFAULTS_FILE = "defaults.json";
    protected static final String CONFIG_FILE = "config.json";
    protected static final String DPOP_KEY_FILE = "dpop-key.enc";
    protected static final String ENC_PREFIX = "enc::";

    private final Path baseDir;
    private final DeviceStoreEncryption encryption;
    private final ObjectMapper mapper;

    protected AbstractFileDeviceStore(Path baseDir, DeviceStoreEncryption encryption) {
        this.baseDir = baseDir;
        this.encryption = encryption;
        this.mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    protected final Path baseDir() {
        return baseDir;
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
        Path file = serverDir(serverUrl).resolve(DPOP_KEY_FILE);
        Files.writeString(file, encryption.encrypt(serverUrl, privateKeyJwk), StandardCharsets.UTF_8);
        restrictPermissions(file);
    }

    @Override
    public String loadDpopPrivateKey(String serverUrl) throws Exception {
        Path file = serverDir(serverUrl).resolve(DPOP_KEY_FILE);
        if (!Files.exists(file)) {
            throw new IllegalStateException(
                "DPoP key not found for " + serverUrl +
                " — initialize and authorize this server first");
        }
        String encrypted = Files.readString(file, StandardCharsets.UTF_8);
        return encryption.decrypt(serverUrl, encrypted);
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
                    }
                    catch (IOException ignored) {
                        // Skip malformed entries.
                    }
                }
            });
        }
        return List.copyOf(servers);
    }

    protected Path serverDir(String serverUrl) {
        return baseDir.resolve(toServerKey(serverUrl));
    }

    public static String toServerKey(String serverUrl) {
        if (serverUrl == null || serverUrl.isBlank()) {
            throw new IllegalArgumentException("Server URL cannot be blank");
        }
        String s = serverUrl;
        if (s.startsWith("https://")) s = s.substring(8);
        else if (s.startsWith("http://")) s = s.substring(7);
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s.replace(':', '_').replace('/', '_');
    }

    protected void ensureBaseDirExists() throws IOException {
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

    protected String encryptToken(String serverUrl, String token) throws Exception {
        if (token == null || token.isBlank()) {
            return token;
        }
        return ENC_PREFIX + encryption.encrypt(serverUrl, token);
    }

    protected String decryptToken(String serverUrl, String token) throws Exception {
        if (token == null || token.isBlank()) {
            return token;
        }
        if (!token.startsWith(ENC_PREFIX)) {
            return token;
        }
        return encryption.decrypt(serverUrl, token.substring(ENC_PREFIX.length()));
    }

    protected static void restrictPermissions(Path file) {
        try {
            Files.setPosixFilePermissions(file,
                Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Best effort on non-POSIX systems.
        }
    }

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
