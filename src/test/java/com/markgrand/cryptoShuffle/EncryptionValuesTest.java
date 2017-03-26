package com.markgrand.cryptoShuffle;

import org.junit.Test;

import java.util.BitSet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for EcryptionsValues
 *
 * @author Mark Grand
 */
@SuppressWarnings("unused")
public class EncryptionValuesTest {
    private final byte[] key = {0x39, (byte) 0xe4, 0x32, (byte) 0xa3, (byte) 0x89, 0x00, 0x24, (byte) 0x97};
    private final byte[] plaintext1 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    private final byte[] encrypted1 = {0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x40, (byte) 0xe1, 0x02, (byte) 0xa3, (byte) 0x94,
            (byte) 0xb5, 0x06, 0x07, 0x08, (byte) 0xf9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    @Test
    public void forEncryptionTest() {
        EncryptionValues ev1 = EncryptionValues.forEncryption(plaintext1, key);
        assertEquals(plaintext1.length, ev1.getPadLength());
        assertEquals(8, ev1.getTargetIndices().length);
        assertEquals(ev1.getEncryptedLength(), ev1.getTargetIndices()[2].length);
        assertEquals(ev1.getEncryptedLength(), plaintext1.length + ev1.getPadLength());
        StringBuilder builder = new StringBuilder();

        BitSet bits = new BitSet(ev1.getEncryptedLength());
        for (int b = 0; b < 8; b++) {
            for (int i = 0; i < ev1.getEncryptedLength(); i++) {
                bits.set((int) ev1.getTargetIndices()[b][i]);
            }
        }
        assertTrue(bits.get(0)
                           && (bits.nextClearBit(0) < 0 || bits.nextClearBit(0) >= ev1.getEncryptedLength()));
    }

    @Test
    public void forDecryptionTest() {
        EncryptionValues ev1 = EncryptionValues.forDecryption(encrypted1, key);
        assertEquals((encrypted1.length - 1) / 2, ev1.getPadLength());
        assertEquals(8, ev1.getTargetIndices().length);
        assertEquals(ev1.getEncryptedLength(), ev1.getTargetIndices()[2].length);
        assertEquals(ev1.getEncryptedLength(), plaintext1.length + ev1.getPadLength());
        StringBuilder builder = new StringBuilder();

        BitSet bits = new BitSet(ev1.getEncryptedLength());
        for (int b = 0; b < 8; b++) {
            for (int i = 0; i < ev1.getEncryptedLength(); i++) {
                bits.set((int) ev1.getTargetIndices()[b][i]);
            }
        }
        assertTrue(bits.get(0)
                           && (bits.nextClearBit(0) < 0 || bits.nextClearBit(0) >= ev1.getEncryptedLength()));
    }
}
