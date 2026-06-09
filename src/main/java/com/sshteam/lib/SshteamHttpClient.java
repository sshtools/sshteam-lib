package com.sshteam.lib;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Thin HTTP client for the SSH Teams server API.
 *
 * <p>Handles form-encoded OAuth2 endpoints and JSON API calls with DPoP proof headers.</p>
 */
public class SshteamHttpClient {

    private final String serverUrl;
    private final HttpClient http;
    private final ObjectMapper mapper;

    public SshteamHttpClient(String serverUrl) {
        this(serverUrl, false);
    }

    /**
     * @param serverUrl the SSH Teams server base URL
     * @param insecure  when {@code true} TLS certificate validation is disabled — for
     *                  development / testing with self-signed certificates only
     */
    public SshteamHttpClient(String serverUrl, boolean insecure) {
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        this.http = buildHttpClient(insecure);
        this.mapper = new ObjectMapper();
    }

    private static HttpClient buildHttpClient(boolean insecure) {
        HttpClient.Builder builder = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10));
        if (insecure) {
            try {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[] { TRUST_ALL }, new SecureRandom());
                builder.sslContext(sslContext);

                // Disable hostname verification (e.g. "localhost" not in SAN)
                SSLParameters sslParams = new SSLParameters();
                sslParams.setEndpointIdentificationAlgorithm("");
                builder.sslParameters(sslParams);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to build insecure SSL context", e);
            }
        }
        return builder.build();
    }

    /** Trust manager that accepts any certificate — ONLY for dev/test use.
     *  Using X509ExtendedTrustManager prevents the JDK from wrapping it in
     *  AbstractTrustManagerWrapper, which would re-apply hostname checking. */
    private static final X509ExtendedTrustManager TRUST_ALL = new X509ExtendedTrustManager() {
        @Override public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
        @Override public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
        @Override public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a, java.net.Socket s) {}
        @Override public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a, java.net.Socket s) {}
        @Override public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a, SSLEngine e) {}
        @Override public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a, SSLEngine e) {}
        @Override public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
    };

    // ── OAuth2 device flow ────────────────────────────────────────────────────

    public JsonNode deviceAuthorize(String clientId, String scope) throws IOException, InterruptedException {
        String body = formEncode(Map.of("client_id", clientId, "scope", scope));
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl + "/oauth2/device_authorization"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        return executeJsonRequest(request, "device_authorization");
    }

    /**
     * Polls the token endpoint with a DPoP proof for the {@code signing} scope.
     *
     * @param clientId   OAuth client ID
     * @param deviceCode device code from the authorization response
     * @param dpopProof  DPoP proof JWT (created for POST to the token endpoint URL)
     */
    public JsonNode pollToken(
        String clientId,
        String deviceCode,
        String dpopProof
    ) throws IOException, InterruptedException {
        String body = formEncode(Map.of(
            "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
            "client_id", clientId,
            "device_code", deviceCode
        ));
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl + "/oauth2/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("DPoP", dpopProof)
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        // Return raw response — caller inspects for authorization_pending / success
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        return mapper.readTree(response.body());
    }

    /**
     * Refreshes a signing-scope access token using the refresh token + DPoP.
     */
    public JsonNode refreshToken(
        String refreshToken,
        String dpopProof
    ) throws IOException, InterruptedException {
        String body = formEncode(Map.of(
            "grant_type", "refresh_token",
            "refresh_token", refreshToken
        ));
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl + "/oauth2/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("DPoP", dpopProof)
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        return executeJsonRequest(request, "refresh_token");
    }

    // ── SSH signing ───────────────────────────────────────────────────────────

    /**
     * Requests an SSH certificate from the server.
     *
     * @param accessToken     the DPoP-bound access token
     * @param dpopProof       DPoP proof JWT created for POST /api/v1/ssh/sign
     * @param publicKey       SSH public key in OpenSSH format
     * @param principal       target UNIX username
     * @param serverFp        server SSH fingerprint
     * @param timezone        IANA timezone (optional)
     * @param certificateType "ED25519" or "RSA"
     */
    public JsonNode sign(
        String accessToken,
        String dpopProof,
        String publicKey,
        String principal,
        String serverFp,
        String timezone,
        String certificateType
    ) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("public_key", publicKey);
        body.put("principal", principal);
        body.put("server_fingerprint", serverFp);
        if (timezone != null && !timezone.isBlank()) {
            body.put("timezone", timezone);
        }
        body.put("certificate_type", certificateType);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl + "/api/v1/ssh/sign"))
            .header("Content-Type", "application/json")
            .header("Authorization", "DPoP " + accessToken)
            .header("DPoP", dpopProof)
            .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
            .build();
        return executeJsonRequest(request, "sign");
    }

    // ── Device management ─────────────────────────────────────────────────────

    /**
     * Revokes a registered device by ID.
     *
     * @param deviceId    the device ID to revoke
     * @param accessToken DPoP-bound access token
     * @param dpopProof   DPoP proof JWT created for DELETE on the revoke URL
     * @return HTTP status code
     */
    public int revokeDevice(
        String deviceId,
        String accessToken,
        String dpopProof
    ) throws IOException, InterruptedException {
        String revokeUrl = serverUrl + "/api/v1/devices/" + deviceId;
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(revokeUrl))
            .header("Authorization", "DPoP " + accessToken)
            .header("DPoP", dpopProof)
            .DELETE()
            .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode();
    }

    // ── Token and endpoint URL helpers ────────────────────────────────────────

    public String tokenEndpointUrl() {
        return serverUrl + "/oauth2/token";
    }

    public String signEndpointUrl() {
        return serverUrl + "/api/v1/ssh/sign";
    }

    public String revokeDeviceUrl(String deviceId) {
        return serverUrl + "/api/v1/devices/" + deviceId;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    // ── private ───────────────────────────────────────────────────────────────

    private JsonNode executeJsonRequest(HttpRequest request, String operation)
        throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new SshteamApiException(operation, response.statusCode(), response.body());
        }
        return mapper.readTree(response.body());
    }

    private static String formEncode(Map<String, String> params) {
        return params.entrySet().stream()
            .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)
                + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
    }

    /** Thrown when the server returns an HTTP error for a known operation. */
    public static class SshteamApiException extends IOException {
        private final int statusCode;
        private final String body;

        public SshteamApiException(String operation, int statusCode, String body) {
            super("Server returned " + statusCode + " for " + operation + ": " + body);
            this.statusCode = statusCode;
            this.body = body;
        }

        public int getStatusCode() { return statusCode; }
        public String getBody() { return body; }
    }
}
