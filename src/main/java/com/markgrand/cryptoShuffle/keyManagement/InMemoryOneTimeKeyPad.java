package com.markgrand.cryptoShuffle.keyManagement;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This is an implementation of {@link OneTimeKeyPad} that runs entirely in memory without a backing store. It is not
 * intended for production use as it will eventually outgrow memory. This is intended primarily as a reference
 * implementation that can be used as the basis for other implementation that do use external storage.
 * @implNote This implementation is thread-safe.
 *
 * @author Mark Grand
 */
public class InMemoryOneTimeKeyPad extends AbstractOneTimeKeyPad implements Serializable {
    private final Map<UUID, byte[]> usedKeys = new ConcurrentHashMap<>();
    private final Map<UUID, byte[]> newKeys = new ConcurrentHashMap<>();
    private final Set<Map.Entry<UUID, byte[]>> newEntrySet = newKeys.entrySet();

    @Override
    protected void addNewKeys(Map<UUID, byte[]> newKeyMap) {
        newKeys.putAll(newKeyMap);
    }

    @Override
    protected Optional<Map.Entry<UUID, byte[]>> doGetUnusedKey() {
        try {
            Iterator<Map.Entry<UUID, byte[]>> iterator = newEntrySet.iterator();
            Map.Entry<UUID, byte[]> nextUnused =  iterator.next();
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
