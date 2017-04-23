package com.markgrand.cryptoShuffle;

import java.util.Random;

import static org.junit.Assert.assertArrayEquals;

/**
 * Unit test for CryptoShuffle that does not have the overhead of JMockit.
 */
public class CryptoShuffleUnmocked {

    //@Test
    private void longTest() {
        final Random random = new Random(19283746576879807L);
        final byte[] longKey = new byte[1000];
        random.nextBytes(longKey);
        final byte[] plaintext = new byte[20000];
        random.nextBytes(plaintext);
        final byte[] encrypted = CryptoShuffle.encrypt(plaintext, longKey);
        final byte[] computedPlainText = CryptoShuffle.decrypt(encrypted, longKey);
        assertArrayEquals(plaintext, computedPlainText);
    }

    public static void main(String[] argv) {
        final long startTime = System.currentTimeMillis();
        new CryptoShuffleUnmocked().longTest();
        System.out.println(System.currentTimeMillis() - startTime);
    }
}
