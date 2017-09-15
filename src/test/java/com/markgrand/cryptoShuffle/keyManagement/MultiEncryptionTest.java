package com.markgrand.cryptoShuffle.keyManagement;

import com.markgrand.cryptoShuffle.AbstractTest;
import org.junit.Test;

import java.security.KeyPair;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class MultiEncryptionTest extends AbstractTest {
    @Test
    public void encryptionAlgorithmTest() {
        Set<KeyPair> keyPairs = generateKeyPairs(3);
        final MultiEncryption multiEncryption
                = new MultiEncryption(key24, keyPairs.stream().map(KeyPair::getPublic).collect(Collectors.toList()));
        assertEquals("RSA", multiEncryption.getEncryptionAlgorithm().name());
    }

    @Test
    public void roundTrip24Test() {
        roundTrip(key24);
    }

    @Test
    public void roundTrip4800Test() {
        roundTrip(key4800);
    }

    private void roundTrip(byte[] plainKey) {
        Set<KeyPair> keyPairs = generateKeyPairs(3);
        final MultiEncryption multiEncryption
                = new MultiEncryption(plainKey, keyPairs.stream().map(KeyPair::getPublic).collect(Collectors.toList()));
        assertFalse(multiEncryption.decrypt(generateKeyPair()).isPresent());
        for (KeyPair keyPair: keyPairs) {
            Optional<byte[]> plainText = multiEncryption.decrypt(keyPair);
            assertTrue(plainText.isPresent());
            assertArrayEquals(plainKey, plainText.get());
        }
    }
}
