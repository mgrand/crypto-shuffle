package com.markgrand.cryptoShuffle.keyShard;

import com.markgrand.cryptoShuffle.AbstractTest;
import static org.junit.Assert.*;

import com.markgrand.cryptoShuffle.keyManagement.AsymmetricEncryptionAlgorithms;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.util.Random;

/**
 * Unit tests for {@link AsymmetricEncryptionAlgorithms}
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
        EncryptedShard encrypted = AsymmetricEncryptionAlgorithms.RSA.encrypt(keyPair.getPublic(), plainText);
        return AsymmetricEncryptionAlgorithms.RSA.decrypt(keyPair.getPrivate(), encrypted);
    }

    @Test
    public void longRoundTripTest() throws Exception {
        byte[] plainText = new byte[800];
        byte[] reconstructedText = rsaRoundTrip(plainText);
        assertArrayEquals(plainText, reconstructedText);
    }
}
