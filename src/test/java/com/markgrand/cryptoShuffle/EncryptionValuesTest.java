package com.markgrand.cryptoShuffle;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for EcryptionsValues
 *
 * @author Mark Grand
 */
@SuppressWarnings("unused")
public class EncryptionValuesTest {
    private final byte[] key = {0x39, (byte) 0xe4, 0x32, (byte) 0xa3, (byte) 0x89, 0x00, 0x24, (byte)0x97};
    private final byte[] plaintext1 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    @Test
    public void constructorTest() {
        EncryptionValues ev1 = new EncryptionValues(plaintext1, key);
        assertEquals(1, ev1.getLengthLength());
        assertTrue(ev1.getPadLength() >= plaintext1.length && ev1.getPadLength() <= 2 * plaintext1.length);
        assertEquals(8, ev1.getTargetIndices().length);
        assertEquals(ev1.getEncryptedLength(), ev1.getTargetIndices()[2].length);
        assertEquals(ev1.getEncryptedLength(), plaintext1.length + ev1.getLengthLength() + 1 + ev1.getPadLength());
        String targetIndicesAsString = "";
        for (int i = 0; i < 8; i++) {
            targetIndicesAsString += "[" + i + "]=" + Arrays.toString(ev1.getTargetIndices()[i]) + "\n";
        }
        for (int i = 0; i < ev1.getEncryptedLength() * 8; i++) {
            assertEquals(targetIndicesAsString, i, ev1.getTargetIndices()[i % 8][i / 8]);
        }
    }
}
