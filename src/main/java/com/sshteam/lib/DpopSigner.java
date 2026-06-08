package com.sshteam.lib;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Generates and signs DPoP proof JWTs per RFC 9449 using an EC P-256 key pair.
 *
 * <p>The private key is kept in memory; callers are responsible for encrypting and persisting
 * it via {@link DeviceStore}.</p>
 */
public class DpopSigner {

    private final ECKey keyPair;

    private DpopSigner(ECKey keyPair) {
        this.keyPair = keyPair;
    }

    /** Generates a fresh EC P-256 DPoP key pair. */
    public static DpopSigner generate() {
        try {
            ECKey key = new ECKeyGenerator(Curve.P_256)
                .keyID(UUID.randomUUID().toString())
                .generate();
            return new DpopSigner(key);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate DPoP key pair", ex);
        }
    }

    /**
     * Restores a {@link DpopSigner} from the full JWK JSON string (including private key).
     * The JSON is obtained by calling {@link #toPrivateKeyJwkJson()} on the original signer.
     */
    public static DpopSigner fromPrivateKeyJwk(String fullJwkJson) {
        try {
            ECKey key = ECKey.parse(fullJwkJson);
            if (!key.isPrivate()) {
                throw new IllegalArgumentException("JWK does not contain a private key");
            }
            return new DpopSigner(key);
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to parse DPoP key JWK", ex);
        }
    }

    /**
     * Creates a DPoP proof JWT for a request without an access token (token endpoint).
     *
     * @param method HTTP method (e.g. "POST")
     * @param htu    absolute URL of the endpoint (no query string)
     */
    public String createProof(String method, String htu) {
        return createProof(method, htu, null);
    }

    /**
     * Creates a DPoP proof JWT for a resource request with a bound access token.
     *
     * @param method      HTTP method
     * @param htu         absolute URL (no query string)
     * @param accessToken the access token — its SHA-256 hash is placed in the {@code ath} claim
     */
    public String createProof(String method, String htu, String accessToken) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(keyPair.toPublicJWK())
                .build();

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", method.toUpperCase())
                .claim("htu", normalizeHtu(htu))
                .issueTime(new Date());

            if (accessToken != null && !accessToken.isBlank()) {
                claims.claim("ath", computeAth(accessToken));
            }

            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new ECDSASigner(keyPair));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to create DPoP proof", ex);
        }
    }

    /** Returns the public-only JWK JSON (safe to share). */
    public String toPublicKeyJwkJson() {
        return keyPair.toPublicJWK().toJSONString();
    }

    /**
     * Returns the full JWK JSON including the private key.
     * This must be encrypted before persisting (see {@link DeviceStore}).
     */
    public String toPrivateKeyJwkJson() {
        return keyPair.toJSONString();
    }

    /** Returns the key ID embedded in the JWK. */
    public String getKeyId() {
        return keyPair.getKeyID();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static String computeAth(String accessToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static String normalizeHtu(String htu) {
        // Strip query string and fragment per RFC 9449 §4.2
        int q = htu.indexOf('?');
        int h = htu.indexOf('#');
        int end = htu.length();
        if (q >= 0) end = Math.min(end, q);
        if (h >= 0) end = Math.min(end, h);
        return htu.substring(0, end);
    }
}
