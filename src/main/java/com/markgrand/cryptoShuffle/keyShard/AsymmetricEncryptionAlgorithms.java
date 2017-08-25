package com.markgrand.cryptoShuffle.keyShard;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAKey;
import java.util.function.BiFunction;

/**
 * Functional interface for asymmetric encryption.
 */
@FunctionalInterface
interface EncryptionFunction extends BiFunction<Key, byte[], EncryptedShard> {
}

/**
 * Functional interface for asymmetric decryption.
 */
@FunctionalInterface
interface DecryptionFunction extends BiFunction<Key, EncryptedShard, byte[]> {
}

/**
 * Named encryption and decryption functions to be used by enum of algorithms.
 */
class AsymmetricEncryptionFunctions {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int PADDING_SIZE = 11;

    static final EncryptionFunction RSA_ENCRYPTION = (key, plaintext) -> {
        RSAKey rsaKey = (RSAKey) key;
        final int maxEncryptablePlaintextBytes = rsaKey.getModulus().bitCount() / 8 - PADDING_SIZE;
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, key);
            if (plaintext.length <= maxEncryptablePlaintextBytes) {
                return new EncryptedShard(key.getEncoded(), rsa.doFinal(plaintext));
            } else {
                SecretKey aesKey = SymmetricEncryptionAlgorithm.AES.generateKey();
                return new EncryptedShard(key.getEncoded(),
                                                 SymmetricEncryptionAlgorithm.AES.encrypt(aesKey, plaintext),
                                                 SymmetricEncryptionAlgorithm.AES, rsa.doFinal(aesKey.getEncoded()));
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException("Error occurred while encrypting", e);
        }
    };

    static final DecryptionFunction RSA_DECRYPTION = (key, encryptedShard) -> {
        final SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm = encryptedShard.getSymmetricEncryptionAlgorithm();
        try {
            if (symmetricEncryptionAlgorithm == null) {
                return rsaDecrypt(key, encryptedShard.getEncryptedShardValue());
            } else {
                byte[] keyText = rsaDecrypt(key, encryptedShard.getEncryptedSymmetricKey());
                return symmetricEncryptionAlgorithm.decrypt(keyText, encryptedShard.getEncryptedShardValue());
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Error occurred while decrypting", e);
        }
    };

    private static byte[] rsaDecrypt(final Key key, final byte[] encryptedText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, key);
        return rsa.doFinal(encryptedText);
    }
}

/**
 * An enumeration of supported asymmetric encryptionFunction algorithms. <p></p> Created by mark.grand on 7/14/2017.
 */
public enum AsymmetricEncryptionAlgorithms {
    RSA(AsymmetricEncryptionFunctions.RSA_ENCRYPTION, AsymmetricEncryptionFunctions.RSA_DECRYPTION);

    private final EncryptionFunction encryptionFunction;
    private final DecryptionFunction decryptionFunction;

    AsymmetricEncryptionAlgorithms(EncryptionFunction encryptionFunction, DecryptionFunction decryptionFunction) {
        this.encryptionFunction = encryptionFunction;
        this.decryptionFunction = decryptionFunction;
    }

    public EncryptedShard encrypt(final Key key, final byte[] plainText) {
        return encryptionFunction.apply(key, plainText);
    }

    public byte[] decrypt(final Key key, final EncryptedShard encryptedShard) {
        return decryptionFunction.apply(key, encryptedShard);
    }
}