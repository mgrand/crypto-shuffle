package com.markgrand.cryptoShuffle.keyManagement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.NotNull;

import java.security.KeyPair;
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
    private final Map<PublicKey, EncryptedShard> encryptions;
    private final AsymmetricEncryptionAlgorithm encryptionAlgorithm;

    /**
     * Constructor to create an {@code EncryptedShard} that uses RSA to encrypt.
     *
     * @param plainText The plain text crypto-shuffle key to be encrypted.
     * @param keys      The keys to use to encrypt the plain text.
     */
    public MultiEncryption(@NotNull final byte[] plainText, @NotNull final Collection<PublicKey> keys) {
        this(AsymmetricEncryptionAlgorithm.RSA,
                encryptWithKeys(plainText, keys, AsymmetricEncryptionAlgorithm.RSA));
    }

    private static Map<PublicKey, EncryptedShard> encryptWithKeys(@NotNull final byte[] plainText,
                                                                  @NotNull final Collection<PublicKey> keys,
                                                                  @SuppressWarnings("SameParameterValue") @NotNull final AsymmetricEncryptionAlgorithm algorithm) {
        final Map<PublicKey, EncryptedShard> encryptionsMap = new HashMap<>();
        for (PublicKey key : keys) {
            encryptionsMap.put(key, algorithm.encrypt(key, plainText));
        }
        return encryptionsMap;
    }

    MultiEncryption(@NotNull final AsymmetricEncryptionAlgorithm algorithm,
                    @NotNull final Map<PublicKey, EncryptedShard> encryptions) {
        encryptionAlgorithm = algorithm;
        this.encryptions = encryptions;
    }

    /**
     * Decrypt the version of the crypto-shuffle key that was encrypted with the given public key.
     *
     * @param keyPair A key pair that contains the public key to look for and the private key to use for decryption.
     * @return If this MultiEncryption contains the given public key, return an {@link Optional} object that contains
     * the decrypted version of the contained crypto-shuffle key. If this object does not contain the given public key,
     * then return an empty {@link Optional} object.
     */
    public Optional<byte[]> decrypt(@NotNull final KeyPair keyPair) {
        return decrypt(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * Decrypt the version of the crypto-shuffle key that was encrypted with the given public key.
     *
     * @param publicKey  The public key to look for.
     * @param privateKey The private key to use for decryption.
     * @return If this MultiEncryption contains the given public key, return an {@link Optional} object that contains
     * the decrypted version of the contained crypto-shuffle key. If this object does not contain the given public key,
     * then return an empty {@link Optional} object.
     */
    public Optional<byte[]> decrypt(@NotNull final PublicKey publicKey, @NotNull final PrivateKey privateKey) {
        return Optional.ofNullable(encryptions.get(publicKey)).map(encryptedShard -> encryptionAlgorithm.decrypt(privateKey, encryptedShard));
    }

    /**
     * Return the encryption algorithm that was used to produce the encrypted text in this object.
     *
     * @return the encrption algorithm.
     */
    @SuppressWarnings("WeakerAccess")
    @NotNull
    public AsymmetricEncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Return the map whose keys are the public keys in this object havings values that are the associated encrypted
     * text.
     *
     * @return the map.
     */
    @SuppressWarnings("WeakerAccess")
    public Map<PublicKey, EncryptedShard> getEncryptions() {
        return encryptions;
    }

    /**
     * Create a JSON representation of this object.
     *
     * @return a JSON representation of this object.
     */
    @SuppressWarnings("WeakerAccess")
    public JsonNode toJson() {
        return JsonUtil.multiEncryptionToJson(this);
    }

    /**
     * Create a {@code MultiEncryption} object from the given JSON
     *
     * @param jsonNode the JSON representation of a MultiEncryption
     * @return the created {@code MultiEncryption} object
     * @throws JsonProcessingException If there is a problem with the JSON.
     */
    @SuppressWarnings("WeakerAccess")
    public static MultiEncryption fromJson(@NotNull final JsonNode jsonNode) throws JsonProcessingException {
        return JsonUtil.jsonToMultiEncryption(jsonNode);
    }

    @Override
    public String toString() {
        return "MultiEncryption{" +
                "encryptions=" + encryptions +
                ", encryptionAlgorithm=" + encryptionAlgorithm +
                '}';
    }
}
