package com.markgrand.cryptoShuffle;

import org.junit.BeforeClass;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

/**
 * <p>Base class for unit tests</p>
 * Created by mark.grand on 7/7/2017.
 */
public abstract class AbstractTest {
    static protected byte[] key4800;
    static protected byte[] key24;

    private static final KeyPairGenerator keyPairGenerator;
    static {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Problem initializing KeyPairGenerator", e);
        }
    }

    @BeforeClass
    public static void initKeys() {
        RandomKeyGenerator generator = new RandomKeyGenerator();
        key4800 = generator.generateKey(4800);
        key24 = generator.generateKey(24);
    }

    /**
     * Generate the given quantity of key pairs
     */
    protected static Set<KeyPair> generateKeyPairs(int quantity) {
        Set<KeyPair> keyPairs = new HashSet<>();
        for (int i = 0; i < quantity; i++) {
            keyPairs.add(generateKeyPair());
        }
        return keyPairs;
    }

    /**
     * Generate a single key pair.
     */
    protected static KeyPair generateKeyPair() {
        return keyPairGenerator.generateKeyPair();
    }
}
