package com.markgrand.cryptoShuffle.keyManagement;

import com.markgrand.cryptoShuffle.RandomKeyGenerator;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Abstract superclass for implementations of {@link OneTimeKeyPad}.
 *
 * @author Mark Grand
 */
public abstract class AbstractOneTimeKeyPad implements OneTimeKeyPad {
    private static final Subroutine NULL_AUTOGENERATE_STRATEGY = () -> {
    };

    private Subroutine autogenerationStrategy = NULL_AUTOGENERATE_STRATEGY;

    @SuppressWarnings("WeakerAccess")
    @Override
    public Map<UUID, byte[]> generateKeys(int count, int keyLength) {
        ensureCountIsPositive(count);
        final RandomKeyGenerator keyGenerator = RandomKeyGenerator.getThreadLocalInstance();
        final Map<UUID, byte[]> newKeyMap = new HashMap<>();
        for (int i = 0; i < count; i++) {
            newKeyMap.put(UUID.randomUUID(), keyGenerator.generateKey(keyLength));
        }
        addNewKeys(newKeyMap);
        return newKeyMap;
    }

    @SuppressWarnings("WeakerAccess")
    @Override
    public Map<UUID, byte[]> generateKeys(int count, int minKeyLength, int maxKeyLength) {
        ensureCountIsPositive(count);
        final RandomKeyGenerator keyGenerator = RandomKeyGenerator.getThreadLocalInstance();
        final Map<UUID, byte[]> newKeyMap = new HashMap<>();
        for (int i = 0; i < count; i++) {
            newKeyMap.put(UUID.randomUUID(), keyGenerator.generateKey(minKeyLength, maxKeyLength));
        }
        addNewKeys(newKeyMap);
        return newKeyMap;
    }

    /**
     * Add the encryption keys in the given map to this {@code OneTimeKeyPad} as new keys.
     *
     * @param newKeyMap the keys to add.
     */
    protected abstract void addNewKeys(Map<UUID, byte[]> newKeyMap);

    private void ensureCountIsPositive(int count) {
        if (count < 1) {
            throw new IllegalArgumentException("count must be greater than zero but is " + count);
        }
    }

    @Override
    public void autoGenerateKeys(int count, int keyLength, Consumer<Map<UUID, byte[]>> transmitter) {
        ensureCountIsPositive(count);
        autogenerationStrategy = () -> {
            final Map<UUID, byte[]> keys = generateKeys(count, keyLength);
            transmitter.accept(keys);
        };
    }

    @Override
    public void autoGenerateKeys(int count, int minKeyLength, int maxKeyLength, Consumer<Map<UUID, byte[]>> transmitter) {
        ensureCountIsPositive(count);
        autogenerationStrategy = () -> {
            final Map<UUID, byte[]> keys = generateKeys(count, minKeyLength, maxKeyLength);
            transmitter.accept(keys);
        };

    }

    @Override
    public Optional<Map.Entry<UUID, byte[]>> getUnusedKey() {
        if (getUnusedKeyCount() == 0) {
            autogenerationStrategy.doIt();
        }
        return doGetUnusedKey();
    }

    /**
     * Return the next unused encryption key in this pad and its UUID.
     * <p>
     * <b>Note: </b> This is called by {@link #getUnusedKey()} after the strategy to {@link #autoGenerateKeys} keys has
     * been run.
     *
     * @return an {@link Optional} object that contains a {@link java.util.Map.Entry} whose value is the encryption key
     * and whose key is the encryption key's UUID, if there are any unused keys in the pad. If there are no unused keys,
     * returns an empty {@code Optional} object.
     */
    protected abstract Optional<Map.Entry<UUID, byte[]>> doGetUnusedKey();

    @Override
    public void clearAutoGenerateKeys() {
        autogenerationStrategy = NULL_AUTOGENERATE_STRATEGY;
    }

    @FunctionalInterface
    private interface Subroutine {
        void doIt();
    }
}
