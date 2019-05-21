package com.markgrand.cryptoShuffle.keyManagement;

import java.io.Serializable;
import java.util.Map;
import java.util.UUID;

/**
 * This interface is implemented by objects that the {@link BasicOneTimeKeyPad} class uses to store used keys
 */
@SuppressWarnings("WeakerAccess")
public interface UsedKeyMap extends Serializable {
    /**
     * Add the given UUID an cryptoshuffle key to this object.
     *
     * @param uuid The UUID to add.
     * @param key  The cryptoshuffle key to add.
     */
    void put(UUID uuid, byte[] key);

    /**
     * Add all pairs of UUIDs and cryptoshuffle keys in the give {@link Map} object to this object.
     *
     * @param map The map containing the UUIDs and keys to be added.
     */
    void putAll(Map<UUID, byte[]> map);

    /**
     * Find the cryptoshuffle key associated in this object with the given UUID.
     *
     * @param uuid The UUID to look up.
     * @return The associated cryptoshuffle key or null if there is no key in this object associated with the given
     * UUID.
     */
    byte[] get(UUID uuid);

    /**
     * Return the number of pairs of UUIDs and cryptshuffle keys in this object.
     *
     * @return the number of pairs of UUIDs and cryptshuffle keys in this object.
     */
    int size();
}
