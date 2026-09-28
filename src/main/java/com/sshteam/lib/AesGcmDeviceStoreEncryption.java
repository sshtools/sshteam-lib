package com.sshteam.lib;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Java 11 compatible AES-GCM {@link DeviceStoreEncryption} implementation.
 *
 * <p>Callers supply key material through {@link SecretSupplier}. This keeps key
 * management outside the library while still providing a portable default
 * encryption implementation.</p>
 */
public final class AesGcmDeviceStoreEncryption implements DeviceStoreEncryption {

    private static final String VERSION_PREFIX = "v1";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretSupplier secretSupplier;
    private final SecureRandom random;

    public AesGcmDeviceStoreEncryption(SecretSupplier secretSupplier) {
        this(secretSupplier, new SecureRandom());
    }

    AesGcmDeviceStoreEncryption(SecretSupplier secretSupplier, SecureRandom random) {
        this.secretSupplier = Objects.requireNonNull(secretSupplier, "secretSupplier cannot be null");
        this.random = Objects.requireNonNull(random, "random cannot be null");
    }

    @Override
    public String encrypt(String serverUrl, String plainText) throws Exception {
        Objects.requireNonNull(plainText, "plainText cannot be null");
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, buildKey(serverUrl), new GCMParameterSpec(TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return VERSION_PREFIX + ":"
            + Base64.getEncoder().encodeToString(iv)
            + ":"
            + Base64.getEncoder().encodeToString(ciphertext);
    }

    @Override
    public String decrypt(String serverUrl, String cipherText) throws Exception {
        Objects.requireNonNull(cipherText, "cipherText cannot be null");
        String[] parts = cipherText.split(":", 3);
        if (parts.length != 3 || !VERSION_PREFIX.equals(parts[0])) {
            throw new IllegalStateException("Unsupported encrypted payload format");
        }

        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] payload = Base64.getDecoder().decode(parts[2]);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, buildKey(serverUrl), new GCMParameterSpec(TAG_BITS, iv));
        byte[] plain = cipher.doFinal(payload);
        return new String(plain, StandardCharsets.UTF_8);
    }

    private SecretKeySpec buildKey(String serverUrl) throws Exception {
        byte[] secret = secretSupplier.secret(serverUrl);
        if (secret == null || secret.length == 0) {
            throw new IllegalStateException("Encryption secret supplier returned no key material");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(secret);
            digest.update((byte) ':');
            digest.update(serverUrl.getBytes(StandardCharsets.UTF_8));
            byte[] key = digest.digest();
            return new SecretKeySpec(key, "AES");
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to derive AES key", e);
        }
    }

    @FunctionalInterface
    public interface SecretSupplier {
        byte[] secret(String serverUrl) throws Exception;
    }
}
