package com.markgrand.cryptoShuffle;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit test for ByteUtil
 */
public class ByteUtilTest {
    @Test
    public void countOnesTest() {
        for (int i = 0; i < 256; i++) {
            assertEquals("For i=" + i, Integer.bitCount(i), ByteUtil.countOnes((byte) i));
        }
    }

    @Test
    public void countOnesArrayTest() {
        byte[] b = {0x33, (byte) 0xf0, 0x01};
        assertEquals(9, ByteUtil.countOnes(b, 0, 3));
    }
}
