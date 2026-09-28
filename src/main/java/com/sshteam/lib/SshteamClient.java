package com.sshteam.lib;

import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.sshtools.client.SshClient;
import com.sshtools.client.SshClient.SshClientBuilder;
import com.sshtools.client.SshClientContext;
import com.sshtools.common.ssh.SshKeyFingerprint;
import com.sshtools.common.publickey.SshKeyPairGenerator;
import com.sshtools.common.publickey.SshKeyUtils;
import com.sshtools.common.ssh.components.SshKeyPair;
import com.sshtools.common.ssh.components.SshPublicKey;

/**
 * High-level SSH Teams client facade that orchestrates device registration,
 * token usage, certificate signing, and device revocation.
 *
 * <p>The client is stateful per server URL but storage remains consumer-owned via
 * {@link DeviceStore}. A single {@link DeviceStore} can be shared across many
 * {@link SshteamClient} instances.</p>
 */
public final class SshteamClient {

    public static final String DEFAULT_REGISTRATION_SCOPE = "signing";

    private final DeviceStore store;
    private final String serverUrl;
    private final boolean ignoreSslTrust;

    public SshteamClient(DeviceStore store, String serverUrl) {
        this(store, serverUrl, false);
    }

    public SshteamClient(DeviceStore store, String serverUrl, boolean ignoreSslTrust) {
        this.store = Objects.requireNonNull(store, "store cannot be null");
        this.serverUrl = ServerUrlNormalizer.normalize(Objects.requireNonNull(serverUrl, "serverUrl cannot be null"));
        this.ignoreSslTrust = ignoreSslTrust;
    }

    public String serverUrl() {
        return serverUrl;
    }

    public RegistrationStart startRegistration(String clientId, String deviceName) throws Exception {
        return startRegistration(clientId, DEFAULT_REGISTRATION_SCOPE, deviceName);
    }

    public RegistrationStart startRegistration(String clientId, String scope, String deviceName) throws Exception {
        store.initServer(serverUrl);
        SshteamHttpClient client = new SshteamHttpClient(serverUrl, ignoreSslTrust);

        JsonNode authResponse = client.deviceAuthorize(clientId, scope, deviceName);
        String deviceCode = text(authResponse, "device_code");
        String userCode = text(authResponse, "user_code");
        String verificationUri = firstPresentText(authResponse, "verification_uri_complete", "verification_uri");
        long expiresIn = authResponse.path("expires_in").asLong(600L);

        return new RegistrationStart(serverUrl, verificationUri, userCode, deviceCode, expiresIn);
    }

    public RegistrationResult register(String clientId, String deviceName,
            int pollIntervalSeconds, int maxWaitSeconds, boolean waitForAuthorization,
            boolean setDefault) throws Exception {
        return register(clientId, DEFAULT_REGISTRATION_SCOPE, deviceName,
                pollIntervalSeconds, maxWaitSeconds, waitForAuthorization, setDefault);
    }

    public RegistrationResult register(String clientId, String scope, String deviceName,
            int pollIntervalSeconds, int maxWaitSeconds, boolean waitForAuthorization,
            boolean setDefault) throws Exception {
        RegistrationStart start = startRegistration(clientId, scope, deviceName);
        if (!waitForAuthorization) {
            return RegistrationResult.pending(
                    start.server(),
                    start.verificationUri(),
                    start.userCode(),
                    start.deviceCode(),
                    "Open verification URI, complete approval, then poll registration.");
        }

        return pollRegistration(clientId, start.deviceCode(), start.verificationUri(), start.userCode(),
                pollIntervalSeconds, maxWaitSeconds, setDefault);
    }

    public RegistrationResult pollRegistration(String clientId, String deviceCode,
            String verificationUri, String userCode,
            int pollIntervalSeconds, int maxWaitSeconds,
            boolean setDefault) throws Exception {
        store.initServer(serverUrl);

        SshteamHttpClient client = new SshteamHttpClient(serverUrl, ignoreSslTrust);
        DpopSigner signer = DpopSigner.generate();

        long waitBudgetMs = Math.max(5, maxWaitSeconds) * 1000L;
        long deadline = System.currentTimeMillis() + waitBudgetMs;

        JsonNode tokenResponse = null;
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(Math.max(1, pollIntervalSeconds) * 1000L);
            String dpopProof = signer.createProof("POST", client.tokenEndpointUrl());
            JsonNode pollResult = client.pollToken(clientId, deviceCode, dpopProof);
            if (pollResult.has("access_token")) {
                tokenResponse = pollResult;
                break;
            }

            String error = pollResult.path("error").asText();
            if ("authorization_pending".equals(error) || "slow_down".equals(error)) {
                continue;
            }
            if ("access_denied".equals(error)) {
                return RegistrationResult.denied(serverUrl, verificationUri, userCode, deviceCode,
                        "Authorization was denied by the user.");
            }
            if ("expired_token".equals(error)) {
                return RegistrationResult.expired(serverUrl, verificationUri, userCode, deviceCode,
                        "Authorization code expired. Restart registration.");
            }
            return RegistrationResult.error(serverUrl, verificationUri, userCode, deviceCode,
                    "Unexpected registration error: " + (error.isBlank() ? "unknown" : error));
        }

        if (tokenResponse == null) {
            return RegistrationResult.pending(serverUrl, verificationUri, userCode, deviceCode,
                    "Authorization still pending. Complete approval and poll again.");
        }

        long now = Instant.now().getEpochSecond();
        long expiresInSecs = tokenResponse.path("expires_in").asLong(86400L);
        String accessToken = text(tokenResponse, "access_token");
        String refreshToken = tokenResponse.has("refresh_token")
                ? tokenResponse.get("refresh_token").asText()
                : null;

        store.saveDpopPrivateKey(serverUrl, signer.toPrivateKeyJwkJson());
        store.saveCredentials(new DeviceCredentials(
                serverUrl,
                accessToken,
                refreshToken,
                now + expiresInSecs,
                signer.getKeyId()));

        boolean defaultUpdated = false;
        if (setDefault || store.getDefaultServer().isEmpty()) {
            store.setDefaultServer(serverUrl);
            defaultUpdated = true;
        }

        return RegistrationResult.authorized(serverUrl, verificationUri, userCode, deviceCode,
                now + expiresInSecs, signer.getKeyId(), defaultUpdated);
    }

    public String getCurrentAccessToken() throws Exception {
        DpopSigner signer = store.loadDpopSigner(serverUrl);
        return store.getCurrentAccessToken(serverUrl, signer, ignoreSslTrust);
    }

    public String requestCertificate(String principal, String serverFingerprint,
            String publicKey, String certificateType, String timezone) throws Exception {
        DpopSigner signer = store.loadDpopSigner(serverUrl);
        SshteamHttpClient client = new SshteamHttpClient(serverUrl, ignoreSslTrust);
        String accessToken = store.getCurrentAccessToken(serverUrl, signer, ignoreSslTrust);

        String requestTimezone = (timezone == null || timezone.isBlank())
                ? ZoneId.systemDefault().getId()
                : timezone;

        String requestCertificateType = (certificateType == null || certificateType.isBlank())
                ? "ED25519"
                : certificateType;

        String dpopProof = signer.createProof("POST", client.signEndpointUrl(), accessToken);
        JsonNode response = client.sign(
                accessToken,
                dpopProof,
                publicKey,
                principal,
                serverFingerprint,
                requestTimezone,
                requestCertificateType);

        String certificate = response.path("certificate").asText().trim();
        if (certificate.isEmpty()) {
            String error = response.path("error").asText();
            throw new IllegalStateException(error.isBlank() ? "Certificate response missing certificate" : error);
        }
        return certificate;
    }

    public SshKeyPair generateEphemeralCertificate(String host, int port, String username, String keyType)
            throws Exception {
        String serverFingerprint = resolveServerFingerprint(host, port);

        SshKeyPair ephemeralKey = SshKeyPairGenerator.generateKeyPair(keyType);
        String publicKey = SshKeyUtils.getOpenSSHFormattedKey(ephemeralKey.getPublicKey()).trim();

        String certificateType = resolveCertificateType(keyType);
        String certificate = requestCertificate(
                username,
                serverFingerprint,
                publicKey,
                certificateType,
                ZoneId.systemDefault().getId());

        SshPublicKey certificatePublicKey = SshKeyUtils.getPublicKey(certificate);
        return SshKeyPair.getKeyPair(ephemeralKey.getPrivateKey(), certificatePublicKey);
    }

    public int revokeDevice(String deviceId) throws Exception {
        DpopSigner signer = store.loadDpopSigner(serverUrl);
        SshteamHttpClient client = new SshteamHttpClient(serverUrl, ignoreSslTrust);
        String accessToken = store.getCurrentAccessToken(serverUrl, signer, ignoreSslTrust);
        String dpopProof = signer.createProof("DELETE", client.revokeDeviceUrl(deviceId), accessToken);
        return client.revokeDevice(deviceId, accessToken, dpopProof);
    }

    public boolean isRegistered() {
        try {
            return store.loadCredentials(serverUrl).isPresent();
        }
        catch (Exception e) {
            return false;
        }
    }

    public List<RegistrationStatusRow> listRegistrations() throws Exception {
        Optional<String> defaultServer = store.getDefaultServer();
        List<String> servers = store.listServers();

        List<RegistrationStatusRow> rows = new ArrayList<>();
        for (String server : servers) {
            Optional<DeviceCredentials> creds = store.loadCredentials(server);
            if (creds.isEmpty()) {
                rows.add(new RegistrationStatusRow(server, server.equals(defaultServer.orElse(null)), false,
                        null, "missing", null));
            }
            else {
                DeviceCredentials credentials = creds.get();
                rows.add(new RegistrationStatusRow(server, server.equals(defaultServer.orElse(null)), true,
                        credentials.keyId(), tokenStatus(credentials), credentials.accessTokenExpiresAt()));
            }
        }
        return rows;
    }

    public List<Map<String, Object>> listRegistrationsAsMaps() throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (RegistrationStatusRow row : listRegistrations()) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("server", row.server());
            map.put("default", row.isDefaultServer());
            map.put("registered", row.isRegistered());
            if (row.keyId() != null) {
                map.put("keyId", row.keyId());
            }
            map.put("accessTokenStatus", row.accessTokenStatus());
            if (row.accessTokenExpiresAt() != null) {
                map.put("accessTokenExpiresAt", row.accessTokenExpiresAt());
            }
            rows.add(map);
        }
        return rows;
    }

    private static String text(JsonNode node, String key) {
        String value = node.path(key).asText();
        if (value.isBlank()) {
            throw new IllegalStateException("Missing expected field: " + key);
        }
        return value;
    }

    private static String firstPresentText(JsonNode node, String primaryKey, String fallbackKey) {
        String primary = node.path(primaryKey).asText();
        if (!primary.isBlank()) {
            return primary;
        }
        return text(node, fallbackKey);
    }

    private static String tokenStatus(DeviceCredentials credentials) {
        if (credentials.accessToken() == null || credentials.accessToken().isBlank()) {
            return "missing";
        }
        long now = Instant.now().getEpochSecond();
        long remaining = credentials.accessTokenExpiresAt() - now;
        if (remaining <= 0) {
            return credentials.refreshToken() == null || credentials.refreshToken().isBlank()
                    ? "expired"
                    : "expired-refresh-available";
        }
        return "valid";
    }

    private static String resolveCertificateType(String keyType) {
        if (SshKeyPairGenerator.ED25519.equals(keyType)) {
            return "ED25519";
        }
        if (SshKeyPairGenerator.SSH2_RSA.equals(keyType)) {
            return "RSA";
        }
        throw new IllegalArgumentException("Unsupported keyType for SSH Teams certificate request: " + keyType);
    }

    private static String resolveServerFingerprint(String host, int port) throws Exception {
        SshClientContext ctx = new SshClientContext();
        ctx.setHostKeyVerification((h, key) -> true);

        try (SshClient probe = SshClientBuilder.create()
                .withHost(host)
                .withPort(port)
                .withUsername("sshteam-probe")
                .withSshContext(ctx)
                .build()) {
            SshPublicKey hostKey = probe.getHostKey();
            if (hostKey == null) {
                throw new IllegalStateException("No host key received from SSH server " + host + ":" + port);
            }
            return SshKeyFingerprint.getFingerprint(hostKey);
        }
    }

    public static final class RegistrationStart {
        private final String server;
        private final String verificationUri;
        private final String userCode;
        private final String deviceCode;
        private final long expiresIn;

        public RegistrationStart(String server, String verificationUri, String userCode,
                String deviceCode, long expiresIn) {
            this.server = server;
            this.verificationUri = verificationUri;
            this.userCode = userCode;
            this.deviceCode = deviceCode;
            this.expiresIn = expiresIn;
        }

        public String server() { return server; }
        public String verificationUri() { return verificationUri; }
        public String userCode() { return userCode; }
        public String deviceCode() { return deviceCode; }
        public long expiresIn() { return expiresIn; }
    }

    public enum RegistrationState {
        AUTHORIZED,
        AUTHORIZATION_PENDING,
        ACCESS_DENIED,
        EXPIRED_TOKEN,
        ERROR
    }

    public static final class RegistrationResult {
        private final RegistrationState status;
        private final String server;
        private final String verificationUri;
        private final String userCode;
        private final String deviceCode;
        private final String message;
        private final Long accessTokenExpiresAt;
        private final String keyId;
        private final Boolean defaultServerUpdated;

        private RegistrationResult(RegistrationState status, String server, String verificationUri,
                String userCode, String deviceCode, String message,
                Long accessTokenExpiresAt, String keyId, Boolean defaultServerUpdated) {
            this.status = status;
            this.server = server;
            this.verificationUri = verificationUri;
            this.userCode = userCode;
            this.deviceCode = deviceCode;
            this.message = message;
            this.accessTokenExpiresAt = accessTokenExpiresAt;
            this.keyId = keyId;
            this.defaultServerUpdated = defaultServerUpdated;
        }

        public RegistrationState status() { return status; }
        public String server() { return server; }
        public String verificationUri() { return verificationUri; }
        public String userCode() { return userCode; }
        public String deviceCode() { return deviceCode; }
        public String message() { return message; }
        public Long accessTokenExpiresAt() { return accessTokenExpiresAt; }
        public String keyId() { return keyId; }
        public Boolean defaultServerUpdated() { return defaultServerUpdated; }

        public static RegistrationResult authorized(String server, String verificationUri,
                String userCode, String deviceCode, long accessTokenExpiresAt,
                String keyId, boolean defaultServerUpdated) {
            return new RegistrationResult(RegistrationState.AUTHORIZED, server, verificationUri, userCode, deviceCode,
                    "Device authorized and credentials saved.", accessTokenExpiresAt, keyId, defaultServerUpdated);
        }

        public static RegistrationResult pending(String server, String verificationUri,
                String userCode, String deviceCode, String message) {
            return new RegistrationResult(RegistrationState.AUTHORIZATION_PENDING, server, verificationUri,
                    userCode, deviceCode, message, null, null, null);
        }

        public static RegistrationResult denied(String server, String verificationUri,
                String userCode, String deviceCode, String message) {
            return new RegistrationResult(RegistrationState.ACCESS_DENIED, server, verificationUri,
                    userCode, deviceCode, message, null, null, null);
        }

        public static RegistrationResult expired(String server, String verificationUri,
                String userCode, String deviceCode, String message) {
            return new RegistrationResult(RegistrationState.EXPIRED_TOKEN, server, verificationUri,
                    userCode, deviceCode, message, null, null, null);
        }

        public static RegistrationResult error(String server, String verificationUri,
                String userCode, String deviceCode, String message) {
            return new RegistrationResult(RegistrationState.ERROR, server, verificationUri,
                    userCode, deviceCode, message, null, null, null);
        }
    }

    public static final class RegistrationStatusRow {
        private final String server;
        private final boolean defaultServer;
        private final boolean registered;
        private final String keyId;
        private final String accessTokenStatus;
        private final Long accessTokenExpiresAt;

        public RegistrationStatusRow(String server, boolean defaultServer, boolean registered,
                String keyId, String accessTokenStatus, Long accessTokenExpiresAt) {
            this.server = server;
            this.defaultServer = defaultServer;
            this.registered = registered;
            this.keyId = keyId;
            this.accessTokenStatus = accessTokenStatus;
            this.accessTokenExpiresAt = accessTokenExpiresAt;
        }

        public String server() { return server; }
        public boolean isDefaultServer() { return defaultServer; }
        public boolean isRegistered() { return registered; }
        public String keyId() { return keyId; }
        public String accessTokenStatus() { return accessTokenStatus; }
        public Long accessTokenExpiresAt() { return accessTokenExpiresAt; }
    }
}
