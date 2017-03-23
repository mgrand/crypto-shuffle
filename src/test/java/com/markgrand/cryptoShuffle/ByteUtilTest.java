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
            assertEquals("For i="+i, Integer.bitCount(i), ByteUtil.countOnes((byte)i));
        }
    }
}
