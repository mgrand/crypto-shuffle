package com.markgrand.cryptoShuffle.keyManagement;

import com.markgrand.cryptoShuffle.AbstractTest;
import org.jetbrains.annotations.NotNull;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class MultiEncryptionTest extends AbstractTest {
    @Test
    public void encryptionAlgorithmTest() {
        Set<KeyPair> keyPairs = generateKeyPairs(3);
        final MultiEncryption multiEncryption = createMultiEncryption(key24, keyPairs);
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
        final MultiEncryption multiEncryption = createMultiEncryption(plainKey, keyPairs);
        assertFalse(multiEncryption.decrypt(generateKeyPair()).isPresent());
        for (KeyPair keyPair: keyPairs) {
            Optional<byte[]> plainText = multiEncryption.decrypt(keyPair);
            assertTrue(plainText.isPresent());
            assertArrayEquals(plainKey, plainText.get());
        }
    }

    @Test
    public void getEncryptionsTest() {
        Set<KeyPair> keyPairs = generateKeyPairs(4);
        final MultiEncryption multiEncryption = createMultiEncryption(key24, keyPairs);
        assertEquals(4, multiEncryption.getEncryptions().size());
    }

    @NotNull
    private MultiEncryption createMultiEncryption(@NotNull final byte[] plainKey,
                                                  @NotNull final Set<KeyPair> keyPairs) {
        return new MultiEncryption(plainKey, keyPairs.stream().map(KeyPair::getPublic).collect(Collectors.toList()));
    }
}
