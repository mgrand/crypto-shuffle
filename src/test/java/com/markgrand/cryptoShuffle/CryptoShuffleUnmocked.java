package com.markgrand.cryptoShuffle;

import org.jetbrains.annotations.NotNull;

import java.util.Random;

import static org.junit.Assert.assertArrayEquals;

/**
 * Unit test for CryptoShuffle that does not have the overhead of JMockit.
 */
@SuppressWarnings("WeakerAccess")
public class CryptoShuffleUnmocked {

    //@Test
    private void longTest() {
        @NotNull final Random random = new Random(19283746576879807L);
        @NotNull final byte[] longKey = new byte[1000];
        random.nextBytes(longKey);
        @NotNull final byte[] plaintext = new byte[20000];
        random.nextBytes(plaintext);
        @NotNull final byte[] encrypted = CryptoShuffle.encrypt(plaintext, longKey);
        @NotNull final byte[] computedPlainText = CryptoShuffle.decrypt(encrypted, longKey);
        assertArrayEquals(plaintext, computedPlainText);
    }

    public static void main(@NotNull String[] argv) {
        final long startTime = System.currentTimeMillis();
        new CryptoShuffleUnmocked().longTest();
        System.out.println(System.currentTimeMillis() - startTime);
    }
}
