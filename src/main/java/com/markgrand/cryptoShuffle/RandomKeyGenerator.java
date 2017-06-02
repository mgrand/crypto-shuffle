package com.markgrand.cryptoShuffle;

import java.security.SecureRandom;

/**
 * Generate random keys to be used with the {@link CryptoShuffle} class.
 * <p>
 * <p>Created by Mark Grand on 5/29/2017.</p>
 */
public class RandomKeyGenerator {
    static private final ThreadLocal<RandomKeyGenerator> localRandom = ThreadLocal.withInitial(RandomKeyGenerator::new);

    private final SecureRandom random = new SecureRandom();

    /**
     * Constructor.
     */
    @SuppressWarnings("WeakerAccess")
    public RandomKeyGenerator() {
    }

    /**
     * This class's {@link #generateKey(int)} method is synchronized. To avoid having calls from multiple threads
     * on the same instance of {@code RandomKeyGenerator} blocking, you can get an instance of
     * {@code RandomKeyGenerator} by calling this method.
     *
     * @return This method will always return the same instance of {@code RandomKeyGenerator} when it is called from the
     * same thread. Calls from two different threads are guaranteed to return different instances of {@code
     * RandomKeyGenerator}.
     */
    public static RandomKeyGenerator getThreadLocalInstance() {
        return localRandom.get();
    }

    private byte[] generateKey0(final int keyLength) {
        final byte[] key = new byte[keyLength];
        random.nextBytes(key);
        return key;
    }

    /**
     * Return a random key of the given length.
     *
     * @param keyLength the length in bytes of the key to be returned. Values less than 8 will be treated as 8.
     */
    public synchronized byte[] generateKey(final int keyLength) {
        if (keyLength < 8) {
            return generateKey0(8);
        }
        return generateKey0(keyLength);
    }

    /**
     * Return a random key whose length is random. The key length will be withing the specified range.
     *
     * @param minKeyLength The minimum length key that will be returned.
     * @param maxKeyLength The maximum length key that will be returned.
     */
    public synchronized byte[] generateKey(final int minKeyLength, final int maxKeyLength) {
        if (minKeyLength < 8) {
            return generateKey(8, maxKeyLength);
        }
        if (minKeyLength >= maxKeyLength) {
            return generateKey0(minKeyLength);
        }
        return generateKey0(minKeyLength + random.nextInt(maxKeyLength - minKeyLength));
    }
}
