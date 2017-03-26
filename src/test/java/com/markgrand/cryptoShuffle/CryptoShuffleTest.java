package com.markgrand.cryptoShuffle;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Unit test for EcryptionsValues
 *
 * @author Mark Grand
 */
@SuppressWarnings("unused")
public class CryptoShuffleTest {
    private final byte[] key = {0x39, (byte) 0xe4, 0x32, (byte) 0xa3, (byte) 0x89, 0x00, 0x24, (byte) 0x97, (byte)0xf1};
    private final byte[] plaintext1 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x40, (byte) 0xe1, 0x02, (byte) 0xa3, (byte) 0x94,
            (byte) 0xb5, 0x06, 0x07, 0x08, (byte) 0xf9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    @Test
    public void encryptionDecryptionTest() {
        byte[] encrypted = CryptoShuffle.encrypt(plaintext1, key);
        assertEquals(1, encrypted[0]);
        assertEquals(plaintext1.length * 2 + 1, encrypted.length);
        assertArrayEquals(plaintext1, CryptoShuffle.decrypt(encrypted, key));
    }
}
