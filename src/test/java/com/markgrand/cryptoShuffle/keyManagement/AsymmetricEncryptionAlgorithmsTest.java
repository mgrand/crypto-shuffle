package com.markgrand.cryptoShuffle.keyManagement;

import com.markgrand.cryptoShuffle.AbstractTest;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.util.Random;

import static org.junit.Assert.assertArrayEquals;

/**
 * Unit tests for {@link AsymmetricEncryptionAlgorithm}
 */
public class AsymmetricEncryptionAlgorithmsTest extends AbstractTest {
    private final static Random random = new Random();

    private static KeyPair keyPair;

    @BeforeClass
    public static void initSuite() {
        keyPair = generateKeyPair();
    }

    @Test
    public void shortRoundTripTest() throws Exception {
        byte[] plainText = new byte[8];
        byte[] reconstructedText = rsaRoundTrip(plainText);
        assertArrayEquals(plainText, reconstructedText);
    }

    private byte[] rsaRoundTrip(byte[] plainText) {
        random.nextBytes(plainText);
        EncryptedShard encrypted = AsymmetricEncryptionAlgorithm.RSA.encrypt(keyPair.getPublic(), plainText);
        return AsymmetricEncryptionAlgorithm.RSA.decrypt(keyPair.getPrivate(), encrypted);
    }

    @Test
    public void roundTripTest4800() throws Exception {
        byte[] reconstructedText = rsaRoundTrip(key4800);
        assertArrayEquals(key4800, reconstructedText);
    }

    @Test
    public void roundTripTest24() throws Exception {
        byte[] reconstructedText = rsaRoundTrip(key24);
        assertArrayEquals(key24, reconstructedText);
    }
}
