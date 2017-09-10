package com.markgrand.cryptoShuffle.keyManagement;

import org.jetbrains.annotations.NotNull;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The crypto-shuffle package includes a convenient mechanism for creating a single JSON object that contains versions
 * of crypto-shuffle keys encrypted by each of a set of public keys. This is the `MultiEncryption` class.
 * <p>
 * To create a `MultiEncryption` object, you pass the constructor a plain text crypto-shuffle key and a collection of
 * one or more public keys. The constructed object contains versions of the crypto-shuffle key encrypted by each of the
 * public keys.
 * <p>
 * To decrypt the contents of a `MultiEncryption` object, pass a public key and its corresponding private key to the
 * `MultiEncryption` object’s `decrypt` method. If the `MultiEncryption` object contains an encrypted crypto-shuffle key
 * that was encrypted with the given public key, it uses the corresponding private key to decrypt the crypto-shuffle
 * key.
 *
 * @author Mark Grand
 */
public class MultiEncryption {
    private final Map<PublicKey, EncryptedShard> encryptions = new HashMap<>();
    private final AsymmetricEncryptionAlgorithm encryptionAlgorithm;

    /**
     * Constructor to create an {@code EncryptedShard} that uses RSA to encrypt.
     *
     * @param plainText           The plain text crypto-shuffle key to be encrypted.
     * @param keys                The keys to use to encrypt the plain text.
     */
    public MultiEncryption(@NotNull final byte[] plainText, @NotNull final Collection<PublicKey> keys) {
        this.encryptionAlgorithm = AsymmetricEncryptionAlgorithm.RSA;
        for (PublicKey key : keys) {
            encryptions.put(key, encryptionAlgorithm.encrypt(key, plainText));
        }
    }

    public Optional<byte[]> decrypt(@NotNull final PublicKey publicKey, @NotNull final PrivateKey privateKey) {
        return Optional.ofNullable(encryptions.get(publicKey)).map(encryptedShard -> encryptionAlgorithm.decrypt(privateKey, encryptedShard));
    }
}
