package com.markgrand.cryptoShuffle.keyShard;

import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.function.BiFunction;

class SymmetricEncryptionAlgorithmHelper {
    static Cipher getAesCipherInstance() {
        try {
            return Cipher.getInstance("AES");
        } catch (@NotNull NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Error getting AES cipher", e);
        }
    }
}

/**
 * <p>Enumeration of supported symmetric encryption algorithms. </p> Created by mark.grand on 7/16/2017.
 */
public enum SymmetricEncryptionAlgorithm {
    AES(aesKeyGenerator(), SymmetricEncryptionAlgorithm::aesEncrypt, SymmetricEncryptionAlgorithm::aesDecrypt);

    @NotNull
    private static synchronized KeyGenerator aesKeyGenerator() {
        try {
            @NotNull KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            return keyGenerator;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected internal error initializing AES encryptionFunction");
        }
    }

    private static byte[] aesEncrypt(SecretKey aesKey, @NotNull byte[] plainText) {
        Cipher aes = SymmetricEncryptionAlgorithmHelper.getAesCipherInstance();
        try {
            aes.init(Cipher.ENCRYPT_MODE, aesKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid key", e);
        }
        try {
            return aes.doFinal(plainText);
        } catch (@NotNull IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Bad encrypted value", e);
        }
    }

    private static byte[] aesDecrypt(@NotNull byte[] key, @NotNull byte[] encryptedText) {
        @NotNull SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        Cipher aes = SymmetricEncryptionAlgorithmHelper.getAesCipherInstance();
        try {
            aes.init(Cipher.DECRYPT_MODE, aesKey);
            return aes.doFinal(encryptedText);
        } catch (@NotNull InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Problem with AES decrypt", e);
        }
    }

    private final KeyGenerator keyGenerator;
    private final BiFunction<SecretKey, byte[], byte[]> encryptionFunction;
    private final BiFunction<byte[], byte[], byte[]> decryptionFunction;

    SymmetricEncryptionAlgorithm(final KeyGenerator keyGenerator,
                                 final BiFunction<SecretKey, byte[], byte[]> encryptionFunction,
                                 final BiFunction<byte[], byte[], byte[]> decryptionFunction) {
        this.keyGenerator = keyGenerator;
        this.encryptionFunction = encryptionFunction;
        this.decryptionFunction = decryptionFunction;
    }

    public SecretKey generateKey() {
        return keyGenerator.generateKey();
    }

    public byte[] encrypt(SecretKey secretKey, byte[] plainText) {
        return encryptionFunction.apply(secretKey, plainText);
    }

    public byte[] decrypt(byte[] key, byte[] encryptedText) {
        return decryptionFunction.apply(key, encryptedText);
    }
}
