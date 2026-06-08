package com.sshteam.lib;

import java.util.Objects;

/**
 * Credentials for one registered device on one SSH Teams server.
 *
 * <p>When loaded from a {@link DeviceStore}, tokens are already decrypted and ready for use.
 * When passed to {@link DeviceStore#saveCredentials}, tokens are plain-text and the store
 * is responsible for encrypting them at rest.</p>
 */
public final class DeviceCredentials {

    private final String serverUrl;
    private final String accessToken;
    private final String refreshToken;
    private final long accessTokenExpiresAt;
    private final String keyId;

    public DeviceCredentials(
        String serverUrl,
        String accessToken,
        String refreshToken,
        long accessTokenExpiresAt,
        String keyId
    ) {
        this.serverUrl = serverUrl;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.accessTokenExpiresAt = accessTokenExpiresAt;
        this.keyId = keyId;
    }

    /** The SSH Teams server base URL. */
    public String serverUrl() { return serverUrl; }

    /** The DPoP-bound access token (plain-text in memory). */
    public String accessToken() { return accessToken; }

    /** The refresh token for token renewal (plain-text in memory, may be null). */
    public String refreshToken() { return refreshToken; }

    /** Unix epoch seconds when the access token expires. */
    public long accessTokenExpiresAt() { return accessTokenExpiresAt; }

    /** The DPoP key ID (kid) associated with this device. */
    public String keyId() { return keyId; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DeviceCredentials)) return false;
        DeviceCredentials that = (DeviceCredentials) o;
        return accessTokenExpiresAt == that.accessTokenExpiresAt
            && Objects.equals(serverUrl, that.serverUrl)
            && Objects.equals(accessToken, that.accessToken)
            && Objects.equals(refreshToken, that.refreshToken)
            && Objects.equals(keyId, that.keyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverUrl, accessToken, refreshToken, accessTokenExpiresAt, keyId);
    }

    @Override
    public String toString() {
        return "DeviceCredentials{serverUrl='" + serverUrl + "', keyId='" + keyId + "'}";
    }
}

