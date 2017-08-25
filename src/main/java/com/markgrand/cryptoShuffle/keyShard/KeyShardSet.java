package com.markgrand.cryptoShuffle.keyShard;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.PublicKey;
import java.util.*;

/**
 * <p>
 * Utility for breaking keys into multiple shards so that they can be securely shared by multiple people.</p>
 * <p>
 * A key shard set consists of a long cryptoshuffle key that has been broken into two or more pieces called shards and
 * some public keys. One or more of the key shards is associated with each of the public keys. The key shards that are
 * associated with a public key are encrypted using that public key. If a key shard is associated with more than one
 * public key, a different copy of the shard will be associated with each public can and encrypted with that public key.
 * </p>
 * <p>
 * Key shards have two distinct uses. They can be used to as a form of information escrow, to require the cooperation
 * and agreement of multiple parties to decrypt a piece of information. For example, if a cryptoshuffle key is split
 * into two shards, each encrypted with a different party's public key, then the two parties will need to cooperate to
 * reconstruct the full cryptoshuffle key and decrypt the cryptoshuffle encrypted text.
 * </p>
 * <p>
 * More elaborate uses of information escrow could require three out of five to agree or get even fancier. In the three
 * out of five case, each public key would be associated with three shards distributed in a way that requires at least
 * three private keys to have all five decrypted shards.
 * </p>
 * <p>
 * The other use of key shards is to provide a way of strengthening the asymmetric encryption used to encrypt the
 * cryptoshuffle keys. If you want to share a cryptoshuffle key with one party but not rely on the security of a single
 * private key then split the cryptoshuffle key into two encrypted shards and someone will need to know two private keys
 * to recover the original cryptoshuffle key.
 * </p>
 * <p>Created by Mark Grand on 6/1/2017.</p>
 */
@SuppressWarnings("WeakerAccess")
public class KeyShardSet {
    private static final int MINIMUM_QUORUM_SIZE = 2;
    private static final int MINIMUM_SHARD_SIZE = 8;

    private final int shardCount;

    @NotNull
    private final ArrayList<KeyShardGroup> groups;

    @NotNull
    private final UUID uuid;

    @NotNull
    private final AsymmetricEncryptionAlgorithms encryptionAlgorithm;

    private KeyShardSet(@NotNull final ArrayList<KeyShardGroup> groups, final int shardCount,
                        @NotNull final UUID uuid,
                        @NotNull final AsymmetricEncryptionAlgorithms encryptionAlgorithm) {
        this.groups = groups;
        this.shardCount = shardCount;
        this.uuid = uuid;
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    /**
     * Create a new builder for a {@code KeyShardSet}
     *
     * @param encryptionAlgorithm The algorithm that will be used to encrypt the key shards.
     * @return the new builder.
     */
    @NotNull
    public static KeyShardingSetBuilder newBuilder(@NotNull final AsymmetricEncryptionAlgorithms encryptionAlgorithm) {
        return new KeyShardingSetBuilder(encryptionAlgorithm);
    }

    @NotNull
    static byte[][] makeShards(@NotNull final byte[] cryptoshuffleKey,
                               final int requiredNumberOfShards, final int shardSize) {
        final byte[][] shards = new byte[requiredNumberOfShards][];
        int remainder = cryptoshuffleKey.length - (shardSize * requiredNumberOfShards);
        int decrement = remainder == 0 ? 0 : ((shardSize + (2 * remainder) - 1) / remainder) - 1;
        int offset = 0;
        for (int i = 0; i < requiredNumberOfShards; i++) {
            int thisShardLength = shardSize;
            if (remainder > 0) {
                thisShardLength += decrement;
                remainder -= decrement;
            }
            shards[i] = new byte[thisShardLength];
            System.arraycopy(cryptoshuffleKey, offset, shards[i], 0, thisShardLength);
            offset += thisShardLength;
        }
        return shards;
    }

    /**
     * Return the keyShardGroups in this {@code KeyShardSet}
     */
    @SuppressWarnings("WeakerAccess")
    public Collection<KeyShardGroup> getGroups() {
        return groups;
    }

    public int getShardCount() {
        return shardCount;
    }

    /**
     * Return the UUID of this {@code @link KeyShardSet}
     */
    @SuppressWarnings("WeakerAccess")
    @NotNull
    public UUID getUuid() {
        return uuid;
    }

    @NotNull
    public AsymmetricEncryptionAlgorithms getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Description of a group of keys that enumerates a set of public keys and the how many private keys will be needed
     * to reconstitute the original cryptoshuffle key.
     */
    @SuppressWarnings("WeakerAccess")
    public static class KeyShardGroup {
        private final int quorumSize;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof KeyShardGroup)) return false;

            KeyShardGroup that = (KeyShardGroup) o;

            return quorumSize == that.quorumSize && keyMap.equals(that.keyMap);
        }

        @Override
        public int hashCode() {
            int result = quorumSize;
            result = 31 * result + keyMap.hashCode();
            return result;
        }

        // Map public keys to
        @NotNull
        private final Map<PublicKey, Map<Integer, EncryptedShard>> keyMap;

        /**
         * Constructor
         *
         * @param quorumSize The minimum number of private keys that will be needed to reconstitute the full
         *                   cryptoshuffle key.
         * @param keys       The public keys that make up this group.
         * @throws IllegalArgumentException If the quorumSize is less than {@value MINIMUM_QUORUM_SIZE} or greater than
         *                                  the number of keys in the group.
         */
        private KeyShardGroup(final int quorumSize, @NotNull final Set<PublicKey> keys) {
            if (quorumSize > keys.size()) {
                @NotNull final String
                        msg = "The quorum size for a group of public keys cannot be greater than the number of keys"
                        + " which is " + keys.size();
                throw new IllegalArgumentException(msg);
            }
            if (quorumSize < MINIMUM_QUORUM_SIZE) {
                @NotNull final String
                        msg = "The quorum size for a group of public keys cannot be less than " + MINIMUM_QUORUM_SIZE;
                throw new IllegalArgumentException(msg);
            }
            this.quorumSize = quorumSize;

            keyMap = new HashMap<>();
            for (PublicKey key : keys) {
                keyMap.put(key, null);
            }
        }

        /**
         * Return the minimum number of private keys that will be needed to reconstitute the full
         * cryptoshuffle key.
         */
        @SuppressWarnings("WeakerAccess")
        public int getQuorumSize() {
            return quorumSize;
        }

        /**
         * Return the public keys in this group.
         */
        @SuppressWarnings("WeakerAccess")
        @NotNull
        public Set<PublicKey> getKeys() {
            return keyMap.keySet();
        }

        /**
         * Associate the given mapping of ordinality to encrypted shard with the given public key.
         *
         * @param key    the public key
         * @param shards The map of ordinalities to encrypted shards.
         */
        void associateEncryptedShardsWithKey(@NotNull PublicKey key, Map<Integer, EncryptedShard> shards) {
            keyMap.put(key, shards);
        }

        /**
         * Return a the shards associated in this group with the specified key.
         * The shards are returned as an {@link Optional} object containing a
         * Map whose entries contain the shard's ordinality as the key and the
         * shard's value as the value. If there are no shards associated with
         * the given key, an empty map is returned.
         */
        @NotNull
        public Map<Integer, EncryptedShard> getEncryptedShardsForKey(@NotNull PublicKey key) {
            //noinspection unchecked
            return keyMap.getOrDefault(key, Collections.EMPTY_MAP);
        }
    }

    @SuppressWarnings("WeakerAccess")
    public static class KeyShardingSetBuilder {
        @NotNull
        private final ArrayList<KeyShardGroup> groups = new ArrayList<>();

        @NotNull
        private final AsymmetricEncryptionAlgorithms encryptionAlgorithm;

        @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
        @NotNull
        private Optional<UUID> uuid = Optional.empty();

        /**
         * Constructor is private to prevent instantiation with {@code new}.
         *
         * @param encryptionAlgorithm A function that will be used to encrypt the key shards. Its first parameter should
         *                           be a public key. The second parameter should be the plain text to be encrypted. The
         *                           return value should be the encrypted text.
         */
        private KeyShardingSetBuilder(@NotNull final AsymmetricEncryptionAlgorithms encryptionAlgorithm) {
            this.encryptionAlgorithm = encryptionAlgorithm;
        }

        /**
         * Add a group of public keys to the {@code KeyShardSet} being built.
         *
         * @param quorumSize The minimum number of private keys that will be needed to reconstitute the full
         *                   cryptoshuffle key.
         * @param keys       The public keys that make up this group.
         * @throws IllegalArgumentException If the quorumSize is less than {@value MINIMUM_QUORUM_SIZE} or greater than
         *                                  the number of keys in the group.
         */
        @NotNull
        public KeyShardingSetBuilder addKeyGroup(final int quorumSize, @NotNull final Set<PublicKey> keys) {
            groups.add(new KeyShardGroup(quorumSize, keys));
            return this;
        }

        /**
         * Set the UUID of the {@link KeyShardSet} being built. This is intended for reconstructing a {@link KeyShardSet}
         * from a serialized form, not for determining the UUID of a new {@link KeyShardSet}
         *
         * @param uuid The UUID for the {@link KeyShardSet} being built
         * @return this builder.
         */
        @NotNull
        public KeyShardingSetBuilder setUuid(@Nullable final UUID uuid) {
            this.uuid = Optional.ofNullable(uuid);
            return this;
        }

        /**
         * Build the specified {@code KeyShardSet}
         *
         * @param cryptoshuffleKey The key to be sharded
         * @return A {@code KeyShardSet} that contains the encrypted shards of the cryptoshuffle key associated with the
         * given public keys.
         * @throws IllegalStateException if dividing the given key into the required number of shards would results in
         *                               shards smaller than {@value MINIMUM_SHARD_SIZE}.
         */
        @NotNull
        public KeyShardSet build(@NotNull final byte[] cryptoshuffleKey) {
            final int requiredNumberOfShards = computeRequiredNumberOfShards();
            final int shardSize = cryptoshuffleKey.length / requiredNumberOfShards;
            checkForMinimumShardSize(cryptoshuffleKey, requiredNumberOfShards, shardSize);
            @NotNull final byte[][] shards = makeShards(cryptoshuffleKey, requiredNumberOfShards, shardSize);
            populateGroups(shards);
            return new KeyShardSet(groups, requiredNumberOfShards, uuid.orElseGet(UUID::randomUUID), encryptionAlgorithm);
        }

        private void populateGroups(@NotNull byte[][] shards) {
            int offset = 0;
            for (final KeyShardGroup group : groups) {
                final Set<PublicKey> publicKeys = group.getKeys();
                final int quorumSize = group.getQuorumSize();
                final int groupKeyCount = publicKeys.size();
                final int shardsPerKey = (quorumSize - 1) * -1 + groupKeyCount;
                int keyIndex = 0;
                for (final PublicKey key : publicKeys) {
                    final Map<Integer, EncryptedShard> encryptedShardOrdinalityMapping = new HashMap<>();
                    for (int keyShardIndex = 0; keyShardIndex < shardsPerKey; keyShardIndex++) {
                        final int shardIndex = offset + ((keyShardIndex + keyIndex) % groupKeyCount);
                        final EncryptedShard encryptedShard = encryptionAlgorithm.encrypt(key, shards[shardIndex]);
                        encryptedShardOrdinalityMapping.put(shardIndex, encryptedShard);
                    }
                    group.associateEncryptedShardsWithKey(key, encryptedShardOrdinalityMapping);
                    keyIndex += 1;
                }
                offset += group.getKeys().size();
            }
        }

        private void checkForMinimumShardSize(@NotNull byte[] cryptoshuffleKey, int requiredNumberOfShards, int shardSize) {
            if (shardSize < MINIMUM_SHARD_SIZE) {
                final String msg = "This key set would contain " + requiredNumberOfShards + " shards."
                        + " The length of the key to be sharded is " + cryptoshuffleKey.length
                        + ". This would result in shards of length " + shardSize
                        + " which is less than the minimum shard size of " + MINIMUM_SHARD_SIZE;
                throw new IllegalStateException(msg);
            }
        }

        private int computeRequiredNumberOfShards() {
            int shardTotal = 0;
            for (KeyShardGroup group : groups) {
                shardTotal += group.getKeys().size();
            }
            return shardTotal;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyShardSet)) return false;

        KeyShardSet that = (KeyShardSet) o;

        return shardCount == that.shardCount && groups.equals(that.groups) && uuid.equals(that.uuid);
    }

    @Override
    public int hashCode() {
        int result = shardCount;
        result = 31 * result + groups.hashCode();
        result = 31 * result + uuid.hashCode();
        return result;
    }
}