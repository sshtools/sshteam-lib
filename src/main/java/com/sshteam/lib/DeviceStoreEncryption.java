package com.sshteam.lib;

/**
 * Encrypts and decrypts persisted device-store values.
 *
 * <p>Implementations are consumer-selectable and can use any backing strategy,
 * including platform KMS, HSM, software keystores, or passphrase-based crypto.</p>
 */
public interface DeviceStoreEncryption {

    /** Encrypt plain text for the given server scope. */
    String encrypt(String serverUrl, String plainText) throws Exception;

    /** Decrypt previously encrypted text for the given server scope. */
    String decrypt(String serverUrl, String cipherText) throws Exception;
}
