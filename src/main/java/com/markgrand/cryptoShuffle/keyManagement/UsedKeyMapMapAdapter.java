package com.markgrand.cryptoShuffle.keyManagement;

import java.util.Map;
import java.util.UUID;

/**
 * An adapter class to allow an object that implements the {@link Map} interface.
 */
public class UsedKeyMapMapAdapter implements UsedKeyMap {
    private final Map<UUID, byte[]> map;

    public UsedKeyMapMapAdapter(Map<UUID, byte[]> map) {
        this.map = map;
    }

    @Override
    public void put(UUID uuid, byte[] key) {
        map.put(uuid, key);
    }

    @Override
    public void putAll(Map<UUID, byte[]> idKeyPairs) {
        map.putAll(idKeyPairs);
    }

    @Override
    public byte[] get(UUID uuid) {
        return map.get(uuid);
    }

    @Override
    public int size() {
        return map.size();
    }
}
