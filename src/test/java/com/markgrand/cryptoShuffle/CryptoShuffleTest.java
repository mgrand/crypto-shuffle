package com.markgrand.cryptoShuffle;

import mockit.Expectations;
import mockit.Mocked;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Unit test for EcryptionsValues
 *
 * @author Mark Grand
 */
@SuppressWarnings("unused")
public class CryptoShuffleTest {
    private final byte[] key = {0x39, (byte) 0xe4, 0x32, (byte) 0xa3, (byte) 0x89, 0x00, 0x24, (byte) 0x97, (byte) 0xf1};
    private final byte[] plaintext16 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x40, (byte) 0xe1, 0x02, (byte) 0xa3, (byte) 0x94,
            (byte) 0xb5, 0x06, 0x07, 0x08, (byte) 0xf9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // {01101100, 10010101}
    private final byte[] plaintext2 = {0x6c, (byte) 0x95};

    @Test
    public void shuffleTest2(@Mocked EncryptionValues ev) {
        new Expectations() {{
            //noinspection ResultOfMethodCallIgnored
            ev.getEncryptedLength();
            result = 4;
            //noinspection ResultOfMethodCallIgnored
            ev.getTargetIndices();
            result = new long[][]{
                    {22, 2, 16, 4},   // [0]
                    {3, 9, 10, 13},   // [1]
                    {12, 21, 17, 28}, // [2]
                    {1, 25, 18, 19},  // [3]
                    {20, 14, 27, 5},  // [4]
                    {8, 30, 7, 6},    // [5]
                    {23, 26, 31, 11}, // [6]
                    {24, 29, 15, 0}}; // [7]
            // Original bit pattern for plaintext2
            //  76543210  76543210
            // {01101100, 10010101}
            // expected shuffle of plaintext2 is
            //  76543210  76543210  76543210  76543210
            // {xxxx011x, x1x1xx01, 1010xxxx, x01xx000}
        }};
        byte[] workingStorage = new byte[ev.getEncryptedLength()];
        System.arraycopy(plaintext2, 0, workingStorage, 0, plaintext2.length);
        byte[] encrypted = CryptoShuffle.shuffle(workingStorage, ev);
        byte[] expectedEncrypted = {0, 0x06, 0x51, (byte)0xa0, 0x20};
        assertArrayEquals(expectedEncrypted, encrypted);
        for (int b = 0; b < 8; b++) {
            for (int i = 0; i < plaintext2.length; i++) {
                int plainValue = ((plaintext2[i] & (1 << b)) != 0) ? 1 : 0;
                int index = (int) (ev.getTargetIndices()[b][i] / 8);
                int bit = (int) (ev.getTargetIndices()[b][i] % 8);
                int encryptedValue = ((encrypted[index + 1] & (1 << bit)) != 0) ? 1 : 0;
                assertEquals("encrypted value is " + Arrays.toString(encrypted), plainValue, encryptedValue);
            }
        }
    }

    @Test
    public void encryptionDecryptionTest() {
        byte[] encrypted = CryptoShuffle.encrypt(plaintext16, key);
        assertEquals(1, encrypted[0]);
        assertEquals(plaintext16.length * 2 + 1, encrypted.length);
        byte[] computedPlaintext = CryptoShuffle.decrypt(encrypted, key);
        assertEquals(ByteUtil.countOnes(plaintext16, 0, plaintext16.length),
                ByteUtil.countOnes(computedPlaintext, 0, computedPlaintext.length));
        assertArrayEquals(plaintext16, computedPlaintext);
    }

    @Test
    public void test2() {
        byte[] plainCopy = Arrays.copyOf(plaintext2, plaintext2.length);
        byte[] encrypted = CryptoShuffle.encrypt(plaintext2, key);
        assertArrayEquals("encrypt modified the plaintext!", plainCopy, plaintext2);
        byte[] computedPlaintext = CryptoShuffle.decrypt(encrypted, key);
        assertEquals(Arrays.toString(computedPlaintext), ByteUtil.countOnes(plaintext2, 0, plaintext2.length),
                ByteUtil.countOnes(computedPlaintext, 1, computedPlaintext.length -1));
        assertArrayEquals("countOnes modified the plaintext!", plainCopy, plaintext2);
        assertArrayEquals(Arrays.toString(computedPlaintext), plaintext2, computedPlaintext);
    }
}
