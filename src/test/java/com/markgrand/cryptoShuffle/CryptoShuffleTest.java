package com.markgrand.cryptoShuffle;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Unit test for EncryptionValues
 *
 * @author Mark Grand
 */
@SuppressWarnings("unused")
public class CryptoShuffleTest extends AbstractCryptoTest {
    @Test
    public void encryptionDecryptionTest() {
        @NotNull byte[] encrypted = CryptoShuffle.encrypt(plaintext16, key16);
        assertEquals(Constants.VERSION, encrypted[0]);
        byte[] decrypted = CryptoShuffle.decrypt(encrypted, key16);
        assertArrayEquals(plaintext16, decrypted);
    }

    /**
     * Test that decrypt throws an {@link IllegalArgumentException} when asked to decrypt something with an unsupported
     * version number.
     */
    @Test(expected = IllegalArgumentException.class)
    public void decryptionWrongVersionTest() {
        @NotNull byte[] encrypted = CryptoShuffle.encrypt(plaintext16, key16);
        encrypted[0]=(byte)0x7f;
        CryptoShuffle.decrypt(encrypted, key16);
    }
}
