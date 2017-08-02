package com.markgrand.cryptoShuffle.keyShard;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.function.BiFunction;

/**
 * Functional interface for asymmetric encryption.
 */
@FunctionalInterface
interface EncryptionFunction extends BiFunction<PublicKey, byte[], EncryptedShard> {
}

/**
 * Functional interface for asymmetric decryption.
 */
@FunctionalInterface
interface DecryptionFunction extends BiFunction<PrivateKey, EncryptedShard, byte[]> {
}

/**
 * Named encryption and decryption functions to be used by enum of algorithms.
 */
class AsymmetricEncryptionFunctions {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int PADDING_SIZE = 11;

    private static KeyGenerator keyGenerator = null;

    private static synchronized KeyGenerator getKeyGenerator() {
        if (keyGenerator == null) {
            try {
                keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(256);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unexpected internal error initializing AES encryptionFunction");
            }
        }
        return keyGenerator;
    }

    static final EncryptionFunction RSA_ENCRYPTION = (publicKey, plaintext) -> {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        final int maxEncryptablePlaintextBytes = rsaPublicKey.getModulus().bitCount() / 8 - PADDING_SIZE;
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            if (plaintext.length <= maxEncryptablePlaintextBytes) {
                return new EncryptedShard(publicKey.getEncoded(), rsa.doFinal(plaintext));
            } else {
                SecretKey aesKey = getKeyGenerator().generateKey();
                Cipher aes = Cipher.getInstance("AES");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                return new EncryptedShard(publicKey.getEncoded(), aes.doFinal(plaintext),
                                                 SymmetricEncryptionAlgorithm.AES, rsa.doFinal(aesKey.getEncoded()));
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException("Error occurred while encrypting", e);
        }
    };

    static final DecryptionFunction RSA_DECRYPTION = (privateKey, encryptedShard) -> {
        final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
        final SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm = encryptedShard.getSymmetricEncryptionAlgorithm();
        try {
            if (symmetricEncryptionAlgorithm == null) {
                return rsaDecrypt(privateKey, encryptedShard.getEncryptedShardValue());
            } else {
                byte[] aesKeyText = rsaDecrypt(privateKey, encryptedShard.getEncryptedSymmetricKey());
                SecretKeySpec aesKey = new SecretKeySpec(aesKeyText, "AES");
                Cipher aes = Cipher.getInstance("AES");
                aes.init(Cipher.DECRYPT_MODE, aesKey);
                return aes.doFinal(encryptedShard.getEncryptedShardValue());
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Error occurred while decrypting", e);
        }
    };

    static byte[] rsaDecrypt(final PrivateKey privateKey, final byte[] encryptedText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        return rsa.doFinal(encryptedText);
    }
}

/**
 * An enumeration of supported assymetric encryptionFunction algorithms. <p></p> Created by mark.grand on 7/14/2017.
 */
public enum AsymmetricEncryptionAlgorithms {
    RSA(AsymmetricEncryptionFunctions.RSA_ENCRYPTION);

    final EncryptionFunction encryptionFunction;

    AsymmetricEncryptionAlgorithms(EncryptionFunction encryption) {
        this.encryptionFunction = encryption;
    }

    EncryptionFunction getEncryptionFunction() {
        return encryptionFunction;
    }
}
