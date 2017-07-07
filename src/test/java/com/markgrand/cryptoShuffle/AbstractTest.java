package com.markgrand.cryptoShuffle;

import org.junit.Before;
import org.junit.BeforeClass;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.BiFunction;

/**
 * <p>Base class for unit tests</p>
 * Created by mark.grand on 7/7/2017.
 */
public abstract class AbstractTest {
    static byte[] key4800;
    static byte[] key24;

    /**
     * Quick trivial function for encryption. Xor's each bytes of the plain text with the first byte of the public key.
     */
    protected final BiFunction<PublicKey, byte[], byte[]> trivialEncryption = (publicKey, plaintext) -> {
        byte[] key = publicKey.getEncoded();
        byte[] result = Arrays.copyOf(plaintext, plaintext.length);
        for (int i = 0; i < result.length; i++) {
            result[i] ^= key[0];
        }
        return result;
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
    Set<KeyPair> generateKeyPairs(int quantity) {
        Set<KeyPair> keyPairs = new HashSet<>();
        for (int i = 0; i < quantity; i++) {
            keyPairs.add(keyPairGenerator.generateKeyPair());
        }
        return keyPairs;
    }
}
