package com.markgrand.cryptoShuffle.keyManagement;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.markgrand.cryptoShuffle.AbstractTest;
import org.jetbrains.annotations.NotNull;
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
            //noinspection ConstantConditions,OptionalGetWithoutIsPresent
            assertArrayEquals(plainKey, multiEncryption.decrypt(keyPair.getPublic(), keyPair.getPrivate()).get());
        }
    }

    @Test
    public void getEncryptionsTest() {
        final Set<KeyPair> keyPairs = generateKeyPairs(4);
        final MultiEncryption multiEncryption = createMultiEncryption(key24, keyPairs);
        assertEquals(4, multiEncryption.getEncryptions().size());
    }

    @NotNull
    private MultiEncryption createMultiEncryption(@NotNull final byte[] plainKey,
                                                  @NotNull final Set<KeyPair> keyPairs) {
        return new MultiEncryption(plainKey, keyPairs.stream().map(KeyPair::getPublic).collect(Collectors.toList()));
    }

    @Test
    public void toStringTest() {
        final Set<KeyPair> keyPairs = generateKeyPairs(4);
        final MultiEncryption multiEncryption = createMultiEncryption(key24, keyPairs);
        final String string = multiEncryption.toString();
        assertTrue(string.contains("MultiEncryption"));
    }

    @Test
    public void jsonRoundTripTest() throws Exception {
        Set<KeyPair> keyPairs = generateKeyPairs(3);
        final MultiEncryption multiEncryption
                = new MultiEncryption(key24, keyPairs.stream().map(KeyPair::getPublic).collect(Collectors.toList()));
        final ObjectNode jsonObject = (ObjectNode) multiEncryption.toJson();
        final MultiEncryption reconstructedMultiEncryption = MultiEncryption.fromJson(jsonObject);
        final Optional<byte[]> reconstructedKey24 = reconstructedMultiEncryption.decrypt(keyPairs.iterator().next());
        assertTrue(reconstructedKey24.isPresent());
        assertArrayEquals(key24, reconstructedKey24.get());
    }
}
