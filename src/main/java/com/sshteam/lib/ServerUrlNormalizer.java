package com.sshteam.lib;

import java.net.URI;
import java.util.Locale;

/**
 * Normalizes SSH Teams server inputs into a canonical base URL.
 *
 * <p>Accepted forms include:</p>
 * <ul>
 *   <li>{@code https://sshteam.com/}</li>
 *   <li>{@code sshteam.com}</li>
 *   <li>{@code https://sshteam.com:8443/}</li>
 *   <li>{@code sshteam.com:443}</li>
 * </ul>
 *
 * <p>When a scheme is omitted, {@code https://} is assumed.</p>
 */
public final class ServerUrlNormalizer {

    private ServerUrlNormalizer() {
    }

    public static String normalize(String rawServerUrl) {
        if (rawServerUrl == null || rawServerUrl.isBlank()) {
            throw new IllegalArgumentException("Server URL cannot be blank");
        }

        String input = rawServerUrl.trim();
        if (!input.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*$")) {
            input = "https://" + input;
        }

        final URI uri;
        try {
            uri = URI.create(input);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid server URL: " + rawServerUrl, ex);
        }

        String scheme = uri.getScheme();
        if (scheme == null || scheme.isBlank()) {
            throw new IllegalArgumentException("Server URL must include a host");
        }
        String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
        if (!"https".equals(normalizedScheme) && !"http".equals(normalizedScheme)) {
            throw new IllegalArgumentException("Server URL scheme must be http or https");
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Server URL must include a host");
        }

        String path = uri.getPath();
        if (path != null && !path.isBlank() && !"/".equals(path)) {
            throw new IllegalArgumentException("Server URL must not include a path");
        }
        if (uri.getQuery() != null || uri.getFragment() != null || uri.getUserInfo() != null) {
            throw new IllegalArgumentException("Server URL must not include user-info, query, or fragment");
        }

        StringBuilder normalized = new StringBuilder();
        normalized.append(normalizedScheme).append("://");

        // URI#getHost strips [] from IPv6; add them back for canonical URL output.
        if (host.contains(":")) {
            normalized.append("[").append(host).append("]");
        } else {
            normalized.append(host);
        }

        if (uri.getPort() != -1) {
            normalized.append(":").append(uri.getPort());
        }

        return normalized.toString();
    }
}