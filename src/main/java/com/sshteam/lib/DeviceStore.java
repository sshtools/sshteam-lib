package com.sshteam.lib;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Abstraction over credential storage for sshteam devices.
 *
 * <p>Supports multiple servers: each server URL maps to its own set of credentials and
 * DPoP key material. One server may be designated as the default, used by CLI commands
 * when no explicit {@code --server} option is given.</p>
 *
 * <p>Implementations are responsible for encrypting tokens and private key material at
 * rest. All values returned from load methods are already decrypted.</p>
 *
 * <p>The {@link FilesystemDeviceStore} is the standard implementation backed by
 * {@code ~/.sshteam/}.</p>
 */
public interface DeviceStore {

    /**
     * Ensures the storage location for the given server is initialised.
     * Must be called before any other operation for a new server.
     */
    void initServer(String serverUrl) throws IOException;

    /**
     * Persists credentials for the given server.
     * Tokens are plain-text; the store encrypts them at rest.
     */
    void saveCredentials(DeviceCredentials credentials) throws Exception;

    /**
     * Loads and decrypts credentials for the given server.
     * Returns empty if the server has not been initialised.
     */
    Optional<DeviceCredentials> loadCredentials(String serverUrl) throws Exception;

    /**
     * Encrypts and persists the DPoP private key JWK for the given server.
     */
    void saveDpopPrivateKey(String serverUrl, String privateKeyJwk) throws Exception;

    /**
     * Loads and decrypts the DPoP private key JWK for the given server.
     *
     * @throws IllegalStateException if no key has been saved for the server
     */
    String loadDpopPrivateKey(String serverUrl) throws Exception;

    /**
     * Sets the default server URL.
     * The default is used by {@link #resolveServer(String)} when no server is specified.
     */
    void setDefaultServer(String serverUrl) throws IOException;

    /** Returns the currently configured default server URL, if any. */
    Optional<String> getDefaultServer() throws IOException;

    /** Returns all server URLs for which credentials have been stored. */
    List<String> listServers() throws IOException;

    // ── convenience defaults ──────────────────────────────────────────────────

    /**
     * Resolves the effective server URL.
     *
     * <p>Returns {@code serverUrl} if it is non-blank; otherwise returns the stored default.
     * Throws {@link IllegalStateException} if neither is available.</p>
     */
    default String resolveServer(String serverUrl) throws IOException {
        if (serverUrl != null && !serverUrl.isBlank()) {
            return serverUrl;
        }
        return getDefaultServer().orElseThrow(() ->
            new IllegalStateException(
                "No server specified and no default server configured. " +
                "Run 'sshteam init <server>' first."));
    }

    /**
     * Constructs a {@link DpopSigner} from the stored private key for the given server.
     */
    default DpopSigner loadDpopSigner(String serverUrl) throws Exception {
        return DpopSigner.fromPrivateKeyJwk(loadDpopPrivateKey(serverUrl));
    }

    /**
     * Returns a valid, decrypted access token for the given server.
     *
     * <p>If the stored token is still valid it is returned immediately. If it is expired (or
     * within 60 s of expiry) and a refresh token is available, the token is automatically
     * refreshed, persisted, and the new access token is returned.</p>
     *
     * @param serverUrl the server to obtain a token for
     * @param signer    the {@link DpopSigner} loaded for that server
     * @throws IllegalStateException if no credentials are stored, or if the token is expired
     *                               and no refresh token is available
     */
    default String getCurrentAccessToken(String serverUrl, DpopSigner signer) throws Exception {
        DeviceCredentials credentials = loadCredentials(serverUrl).orElseThrow(() ->
            new IllegalStateException(
                "Not initialised for " + serverUrl +
                " — run 'sshteam init " + serverUrl + "' first"));

        long now = Instant.now().getEpochSecond();
        if (now < credentials.accessTokenExpiresAt() - 60) {
            return credentials.accessToken();
        }

        String refreshToken = credentials.refreshToken();
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalStateException(
                "Access token expired and no refresh token available. " +
                "Run 'sshteam init " + serverUrl + "' again.");
        }

        SshteamHttpClient client = new SshteamHttpClient(serverUrl);
        String dpopProof = signer.createProof("POST", client.tokenEndpointUrl());
        JsonNode refreshResult = client.refreshToken(refreshToken, dpopProof);

        if (!refreshResult.has("access_token") || refreshResult.get("access_token").asText().isBlank()) {
            throw new IllegalStateException("Token refresh failed: no access_token returned by server");
        }

        String newAccessToken = refreshResult.get("access_token").asText();
        String newRefreshToken = refreshResult.has("refresh_token")
            ? refreshResult.get("refresh_token").asText()
            : refreshToken;
        long expiresIn = refreshResult.has("expires_in")
            ? refreshResult.get("expires_in").asLong()
            : 86400;

        saveCredentials(new DeviceCredentials(
            serverUrl,
            newAccessToken,
            newRefreshToken,
            now + expiresIn,
            credentials.keyId()
        ));

        return newAccessToken;
    }
}
