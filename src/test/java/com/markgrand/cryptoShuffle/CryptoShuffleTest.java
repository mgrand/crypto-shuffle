package com.markgrand.cryptoShuffle;

import mockit.Expectations;
import mockit.Mocked;
import org.junit.Test;

import java.util.Arrays;

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
        byte[] expectedEncrypted = {0, 0x06, 0x51, (byte) 0xa0, 0x20};
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
                ByteUtil.countOnes(computedPlaintext, 0, computedPlaintext.length));
        assertArrayEquals("countOnes modified the plaintext!", plainCopy, plaintext2);
        assertArrayEquals(Arrays.toString(computedPlaintext), plaintext2, computedPlaintext);
    }
}
