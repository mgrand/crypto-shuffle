package com.markgrand.cryptoShuffle;

import org.jetbrains.annotations.NotNull;

/**
 * Superclass to provide common data and logic for unit tests.
 */
public class AbstractCryptoTest {
    @NotNull
    static final byte[] key = {0x39, (byte) 0xe4, 0x32, (byte) 0xa3, (byte) 0x89, 0x00, 0x24, (byte) 0x97, (byte) 0xf1};

    @NotNull
    static final byte[] plaintext16 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    @NotNull
    static final byte[] plaintext2 = {0x6c, (byte) 0x95};
}
