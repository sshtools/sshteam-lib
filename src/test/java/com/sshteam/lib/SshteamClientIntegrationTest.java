package com.sshteam.lib;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class SshteamClientIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HttpServer server;
    private String baseUrl;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void registerWithoutWaitingReturnsPending() throws Exception {
        server.createContext("/oauth2/device_authorization", exchange -> {
            assertThat(exchange.getRequestMethod()).isEqualTo("POST");
                        writeJson(exchange, 200,
                                        "{\"device_code\":\"dc-1\",\"user_code\":\"uc-1\","
                                        + "\"verification_uri_complete\":\"https://verify.example/complete\",\"expires_in\":600}");
        });
        server.start();

        InMemoryDeviceStore store = new InMemoryDeviceStore();
        SshteamClient client = new SshteamClient(store, baseUrl);

        SshteamClient.RegistrationResult result = client.register(
            "sshteam-cli", "test-device",
                1, 5, false, false);

        assertThat(result.status()).isEqualTo(SshteamClient.RegistrationState.AUTHORIZATION_PENDING);
        assertThat(result.deviceCode()).isEqualTo("dc-1");
        assertThat(result.userCode()).isEqualTo("uc-1");
        assertThat(store.loadCredentials(baseUrl)).isEmpty();
    }

    @Test
    void registerWithPollingStoresCredentialsAndSetsDefault() throws Exception {
        AtomicInteger pollCount = new AtomicInteger();

                server.createContext("/oauth2/device_authorization", exchange -> writeJson(exchange, 200,
                                "{\"device_code\":\"device-1\",\"user_code\":\"user-1\","
                                + "\"verification_uri_complete\":\"https://verify.example/complete\",\"expires_in\":60}"));

        server.createContext("/oauth2/token", exchange -> {
            String body = readBody(exchange);
            JsonNode form = formToJson(body);
            String grantType = form.path("grant_type").asText();
            if ("urn:ietf:params:oauth:grant-type:device_code".equals(grantType)) {
                int call = pollCount.incrementAndGet();
                if (call == 1) {
                    writeJson(exchange, 200, "{" +
                            "\"error\":\"authorization_pending\"" +
                            "}");
                    return;
                }
                writeJson(exchange, 200,
                        "{\"access_token\":\"access-1\",\"refresh_token\":\"refresh-1\",\"expires_in\":3600}");
                return;
            }
            throw new AssertionError("Unexpected grant_type: " + grantType);
        });

        server.start();

        InMemoryDeviceStore store = new InMemoryDeviceStore();
        SshteamClient client = new SshteamClient(store, baseUrl);

        SshteamClient.RegistrationResult result = client.register(
            "sshteam-cli", "test-device",
                1, 6, true, true);

        assertThat(result.status()).isEqualTo(SshteamClient.RegistrationState.AUTHORIZED);
        assertThat(result.defaultServerUpdated()).isTrue();
        assertThat(result.keyId()).isNotBlank();

        DeviceCredentials credentials = store.loadCredentials(baseUrl).orElseThrow();
        assertThat(credentials.accessToken()).isEqualTo("access-1");
        assertThat(credentials.refreshToken()).isEqualTo("refresh-1");
        assertThat(credentials.keyId()).isEqualTo(result.keyId());

        String privateJwk = store.loadDpopPrivateKey(baseUrl);
        assertThat(privateJwk).contains("\"kty\":\"EC\"");

        assertThat(store.getDefaultServer()).contains(baseUrl);
    }

    @Test
    void pollRegistrationDeniedReturnsDenied() throws Exception {
        server.createContext("/oauth2/token", exchange -> writeJson(exchange, 200, "{\"error\":\"access_denied\"}"));
        server.start();

        InMemoryDeviceStore store = new InMemoryDeviceStore();
        SshteamClient client = new SshteamClient(store, baseUrl);

        SshteamClient.RegistrationResult result = client.pollRegistration(
                "sshteam-cli", "device-1", "https://verify.example", "user-1",
                1, 5, false);

        assertThat(result.status()).isEqualTo(SshteamClient.RegistrationState.ACCESS_DENIED);
        assertThat(store.loadCredentials(baseUrl)).isEmpty();
    }

    @Test
    void requestCertificateUsesStoredIdentityAndReturnsCertificate() throws Exception {
        server.createContext("/api/v1/ssh/sign", exchange -> {
            assertThat(exchange.getRequestMethod()).isEqualTo("POST");
            assertThat(exchange.getRequestHeaders().getFirst("Authorization")).startsWith("DPoP ");
            assertThat(exchange.getRequestHeaders().getFirst("DPoP")).isNotBlank();
            writeJson(exchange, 200, "{\"certificate\":\"ssh-ed25519-cert-v01@openssh.com AAAATEST\"}");
        });
        server.start();

        InMemoryDeviceStore store = new InMemoryDeviceStore();
        DpopSigner signer = DpopSigner.generate();
        store.saveDpopPrivateKey(baseUrl, signer.toPrivateKeyJwkJson());
        store.saveCredentials(new DeviceCredentials(
                baseUrl,
                "access-token",
                "refresh-token",
                Instant.now().getEpochSecond() + 3600,
                signer.getKeyId()));

        SshteamClient client = new SshteamClient(store, baseUrl);

        String certificate = client.requestCertificate(
                "lee",
                "SHA256:abcdef",
                "ssh-ed25519 AAAATEST",
                "ED25519",
                "UTC");

        assertThat(certificate).isEqualTo("ssh-ed25519-cert-v01@openssh.com AAAATEST");
    }

    @Test
    void revokeDeviceUsesStoredIdentityAndReturnsStatusCode() throws Exception {
        server.createContext("/api/v1/devices/device-123", exchange -> {
            assertThat(exchange.getRequestMethod()).isEqualTo("DELETE");
            assertThat(exchange.getRequestHeaders().getFirst("Authorization")).startsWith("DPoP ");
            assertThat(exchange.getRequestHeaders().getFirst("DPoP")).isNotBlank();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.start();

        InMemoryDeviceStore store = new InMemoryDeviceStore();
        DpopSigner signer = DpopSigner.generate();
        store.saveDpopPrivateKey(baseUrl, signer.toPrivateKeyJwkJson());
        store.saveCredentials(new DeviceCredentials(
                baseUrl,
                "access-token",
                "refresh-token",
                Instant.now().getEpochSecond() + 3600,
                signer.getKeyId()));

        SshteamClient client = new SshteamClient(store, baseUrl);

        int status = client.revokeDevice("device-123");
        assertThat(status).isEqualTo(204);
    }

    @Test
    void getCurrentAccessTokenRefreshesWhenExpired() throws Exception {
        server.createContext("/oauth2/token", exchange -> {
            String body = readBody(exchange);
            JsonNode form = formToJson(body);
            assertThat(form.path("grant_type").asText()).isEqualTo("refresh_token");
            assertThat(form.path("refresh_token").asText()).isEqualTo("refresh-old");
                        writeJson(exchange, 200,
                                        "{\"access_token\":\"access-new\",\"refresh_token\":\"refresh-new\",\"expires_in\":7200}");
        });
        server.start();

        InMemoryDeviceStore store = new InMemoryDeviceStore();
        DpopSigner signer = DpopSigner.generate();
        store.saveDpopPrivateKey(baseUrl, signer.toPrivateKeyJwkJson());
        store.saveCredentials(new DeviceCredentials(
                baseUrl,
                "access-old",
                "refresh-old",
                Instant.now().getEpochSecond() - 60,
                signer.getKeyId()));

        SshteamClient client = new SshteamClient(store, baseUrl);

        String token = client.getCurrentAccessToken();
        assertThat(token).isEqualTo("access-new");

        DeviceCredentials refreshed = store.loadCredentials(baseUrl).orElseThrow();
        assertThat(refreshed.accessToken()).isEqualTo("access-new");
        assertThat(refreshed.refreshToken()).isEqualTo("refresh-new");
        assertThat(refreshed.accessTokenExpiresAt()).isGreaterThan(Instant.now().getEpochSecond());
    }

    @Test
    void requestCertificateFailsWhenCertificateMissing() throws Exception {
        server.createContext("/api/v1/ssh/sign", exchange ->
                writeJson(exchange, 200, "{\"error\":\"principal not permitted\"}"));
        server.start();

        InMemoryDeviceStore store = new InMemoryDeviceStore();
        DpopSigner signer = DpopSigner.generate();
        store.saveDpopPrivateKey(baseUrl, signer.toPrivateKeyJwkJson());
        store.saveCredentials(new DeviceCredentials(
                baseUrl,
                "access-token",
                "refresh-token",
                Instant.now().getEpochSecond() + 3600,
                signer.getKeyId()));

        SshteamClient client = new SshteamClient(store, baseUrl);

        assertThatThrownBy(() -> client.requestCertificate(
                "lee", "SHA256:abcdef", "ssh-ed25519 AAAATEST", "ED25519", "UTC"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("principal not permitted");
    }

    @Test
    void listRegistrationsBuildsStatusRows() throws Exception {
        InMemoryDeviceStore store = new InMemoryDeviceStore();
        String otherServer = baseUrl + "-other";

        DpopSigner signer1 = DpopSigner.generate();
        store.saveCredentials(new DeviceCredentials(
                baseUrl, "token-valid", "refresh-1", Instant.now().getEpochSecond() + 3600, signer1.getKeyId()));

        DpopSigner signer2 = DpopSigner.generate();
        store.saveCredentials(new DeviceCredentials(
                otherServer, "token-expired", "", Instant.now().getEpochSecond() - 1, signer2.getKeyId()));

        store.setDefaultServer(baseUrl);

        SshteamClient client = new SshteamClient(store, baseUrl);

        Map<String, SshteamClient.RegistrationStatusRow> byServer = client.listRegistrations().stream()
                .collect(java.util.stream.Collectors.toMap(SshteamClient.RegistrationStatusRow::server, r -> r));

        assertThat(byServer.get(baseUrl).isRegistered()).isTrue();
        assertThat(byServer.get(baseUrl).isDefaultServer()).isTrue();
        assertThat(byServer.get(baseUrl).accessTokenStatus()).isEqualTo("valid");

        assertThat(byServer.get(otherServer).isRegistered()).isTrue();
        assertThat(byServer.get(otherServer).isDefaultServer()).isFalse();
        assertThat(byServer.get(otherServer).accessTokenStatus()).isEqualTo("expired");
    }

    private static void writeJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static JsonNode formToJson(String formEncoded) throws IOException {
        String[] parts = formEncoded.split("&");
        StringBuilder json = new StringBuilder("{");
        for (int i = 0; i < parts.length; i++) {
            String[] kv = parts[i].split("=", 2);
            String key = java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1
                    ? java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8)
                    : "";
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(key).append('"').append(':').append('"').append(value).append('"');
        }
        json.append('}');
        return MAPPER.readTree(json.toString());
    }
}
