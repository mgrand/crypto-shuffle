package com.markgrand.cryptoShuffle;

import org.junit.Before;
import org.junit.BeforeClass;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.HashSet;
import java.util.Set;
import java.util.function.BiFunction;

/**
 * <p>Base class for unit tests</p>
 * Created by mark.grand on 7/7/2017.
 */
public abstract class AbstractTest {
    static protected byte[] key4800;
    static protected byte[] key24;

    /**
     * Function for encryption.
     */
    protected final BiFunction<PublicKey, byte[], byte[]> rsaEncryption = (publicKey, plaintext) -> {
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            return rsa.doFinal(plaintext);
        } catch (NoSuchAlgorithmException|NoSuchPaddingException |IllegalBlockSizeException|BadPaddingException|InvalidKeyException e) {
            throw new RuntimeException("Error occurred while encrypting", e);
        }
    };
    private KeyPairGenerator keyPairGenerator ;

    @BeforeClass
    public static void initKeys() {
        RandomKeyGenerator generator = new RandomKeyGenerator();
        key4800 = generator.generateKey(4800);
        key24 = generator.generateKey(24);
    }

    @Before
    public void init() throws Exception {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    }

    /**
     * Generate the given quantity of key pairs
     */
    protected Set<KeyPair> generateKeyPairs(int quantity) {
        Set<KeyPair> keyPairs = new HashSet<>();
        for (int i = 0; i < quantity; i++) {
            keyPairs.add(keyPairGenerator.generateKeyPair());
        }
        return keyPairs;
    }
}
