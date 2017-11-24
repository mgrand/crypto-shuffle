package com.markgrand.cryptoShuffle.keyManagement;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This is a basic implementation of the {@link OneTimeKeyPad} interface.  It can work as an in-memory one time pad.
 *
 * @author Mark Grand
 */
public class BasicOneTimeKeyPad extends AbstractOneTimeKeyPad implements Serializable {
    private final UsedKeyMap usedKeys;
    private final Map<UUID, byte[]> newKeys = new ConcurrentHashMap<>();
    private final Set<Map.Entry<UUID, byte[]>> newEntrySet = newKeys.entrySet();

    /**
     * Construct a {@link OneTimeKeyPad} that uses a {@link ConcurrentHashMap} to keep used keys in memory.
     */
    public BasicOneTimeKeyPad() {
        usedKeys = new UsedKeyMapMapAdapter(new ConcurrentHashMap<>());
    }

    /**
     * Construct a {@link OneTimeKeyPad} that uses the given {@link UsedKeyMap} object to store used keys.
     *
     * @param usedKeyMap the object to use to store used keys.
     */
    public BasicOneTimeKeyPad(UsedKeyMap usedKeyMap) {
        usedKeys = usedKeyMap;
    }

    @Override
    protected void addNewKeys(Map<UUID, byte[]> newKeyMap) {
        newKeys.putAll(newKeyMap);
    }

    @Override
    protected Optional<Map.Entry<UUID, byte[]>> doGetUnusedKey() {
        try {
            Iterator<Map.Entry<UUID, byte[]>> iterator = newEntrySet.iterator();
            Map.Entry<UUID, byte[]> nextUnused = iterator.next();
            iterator.remove();
            usedKeys.put(nextUnused.getKey(), nextUnused.getValue());
            return Optional.of(nextUnused);
        } catch (NoSuchElementException e) {
            return Optional.empty();
        }
    }

    @Override
    public void addSharedKeys(Map<UUID, byte[]> sharedKeyMap) {
        usedKeys.putAll(sharedKeyMap);
    }

    @Override
    public Optional<byte[]> lookupKey(UUID uuid) {
        return Optional.ofNullable(usedKeys.get(uuid));
    }

    @Override
    public int getUnusedKeyCount() {
        return newKeys.size();
    }

    @Override
    public int getUsedKeyCount() {
        return usedKeys.size();
    }
}
