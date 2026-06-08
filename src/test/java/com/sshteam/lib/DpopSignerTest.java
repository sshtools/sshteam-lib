package com.sshteam.lib;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

class DpopSignerTest {

    @Test
    void generatesKeyAndCreatesValidProof() throws Exception {
        DpopSigner signer = DpopSigner.generate();

        String proof = signer.createProof("POST", "http://localhost:8888/oauth2/token");

        SignedJWT jwt = SignedJWT.parse(proof);
        assertThat(jwt.getHeader().getType().getType()).isEqualTo("dpop+jwt");
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        assertThat(jwt.getHeader().getJWK()).isNotNull();
        assertThat(jwt.getJWTClaimsSet().getStringClaim("htm")).isEqualTo("POST");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("htu")).isEqualTo("http://localhost:8888/oauth2/token");
        assertThat(jwt.getJWTClaimsSet().getJWTID()).isNotBlank();
        assertThat(jwt.getJWTClaimsSet().getIssueTime()).isNotNull();

        // Verify signature is valid against embedded public key
        ECKey pubKey = (ECKey) jwt.getHeader().getJWK();
        JWSVerifier verifier = new ECDSAVerifier(pubKey);
        assertThat(jwt.verify(verifier)).isTrue();
    }

    @Test
    void createsProofWithAth() throws Exception {
        DpopSigner signer = DpopSigner.generate();
        String accessToken = "example-access-token-value";

        String proof = signer.createProof("POST", "http://localhost:8888/api/v1/ssh/sign", accessToken);

        SignedJWT jwt = SignedJWT.parse(proof);
        String ath = jwt.getJWTClaimsSet().getStringClaim("ath");
        assertThat(ath).isNotBlank();

        // Verify ath = base64url(SHA-256(access_token))
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
        String expectedAth = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        assertThat(ath).isEqualTo(expectedAth);
    }

    @Test
    void proofWithoutAthHasNoAthClaim() throws Exception {
        DpopSigner signer = DpopSigner.generate();
        String proof = signer.createProof("GET", "http://localhost:8888/api/v1/devices");

        SignedJWT jwt = SignedJWT.parse(proof);
        assertThat(jwt.getJWTClaimsSet().getClaims().containsKey("ath")).isFalse();
    }

    @Test
    void eachProofHasUniqueJti() throws Exception {
        DpopSigner signer = DpopSigner.generate();

        String proof1 = signer.createProof("POST", "http://localhost:8888/oauth2/token");
        String proof2 = signer.createProof("POST", "http://localhost:8888/oauth2/token");

        String jti1 = SignedJWT.parse(proof1).getJWTClaimsSet().getJWTID();
        String jti2 = SignedJWT.parse(proof2).getJWTClaimsSet().getJWTID();

        assertThat(jti1).isNotEqualTo(jti2);
    }

    @Test
    void roundTripsPrivateKeyThroughJson() throws Exception {
        DpopSigner original = DpopSigner.generate();
        String privateJwk = original.toPrivateKeyJwkJson();

        DpopSigner restored = DpopSigner.fromPrivateKeyJwk(privateJwk);

        // Same key ID
        assertThat(restored.getKeyId()).isEqualTo(original.getKeyId());

        // Proofs from restored signer verify against same public key
        String proof = restored.createProof("POST", "http://localhost:8888/oauth2/token");
        SignedJWT jwt = SignedJWT.parse(proof);
        ECKey pubKey = (ECKey) jwt.getHeader().getJWK();
        JWSVerifier verifier = new ECDSAVerifier(pubKey);
        assertThat(jwt.verify(verifier)).isTrue();
    }

    @Test
    void publicKeyJwkContainsNoPrivateMaterial() throws Exception {
        DpopSigner signer = DpopSigner.generate();
        String pubJwk = signer.toPublicKeyJwkJson();

        assertThat(pubJwk).doesNotContain("\"d\":");  // d is the EC private key component
        assertThat(pubJwk).contains("\"crv\":\"P-256\"");
        assertThat(pubJwk).contains("\"kty\":\"EC\"");
    }

    @Test
    void differentKeysHaveDifferentKeyIds() throws Exception {
        DpopSigner signer1 = DpopSigner.generate();
        DpopSigner signer2 = DpopSigner.generate();

        assertThat(signer1.getKeyId()).isNotEqualTo(signer2.getKeyId());
    }

    @Test
    void fromPrivateKeyJwkRejectsPublicKeyOnly() throws Exception {
        DpopSigner signer = DpopSigner.generate();
        String pubJwk = signer.toPublicKeyJwkJson();

        assertThatThrownBy(() -> DpopSigner.fromPrivateKeyJwk(pubJwk))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("private key");
    }
}
