package com.markgrand.cryptoShuffle.keyManagement;

import com.markgrand.cryptoShuffle.keyManagement.AsymmetricEncryptionAlgorithm;
import org.jetbrains.annotations.NotNull;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

/**
 * <b>This class is not ready for use. <u>Please do not use it.</u></b>
 * <p>
 * Utility for breaking keys into multiple shards so that they can be securely shared by multiple people.
 * <p>
 * A key shard set consists of a long cryptoshuffle key that has been broken into two or more pieces called shards and
 * some public keys. One or more of the key shards is associated with each of the public keys. The key shards that are
 * associated with a public key are encrypted using that public key. If a key shard is associated with more than one
 * public key, a different copy of the shard will be associated with each public can and encrypted with that public
 * key.
 * <p>
 * Key shards have two distinct uses. They can be used to as a form of information escrow, to require the cooperation
 * and agreement of multiple parties to decrypt a piece of information. For example, if a cryptoshuffle key is split
 * into two shards, each encrypted with a different party's public key, then the two parties will need to cooperate to
 * reconstruct the full cryptoshuffle key and decrypt the cryptoshuffle encrypted text.
 * <p>
 * More elaborate uses of information escrow could require three out of five to agree or get even fancier. In the three
 * out of five case, each public key would be associated with three shards distributed in a way that requires at least
 * three private keys to have all five decrypted shards.
 * <p>
 * The other use of key shards is to provide a way of strengthening the asymmetric encryption used to encrypt the
 * cryptoshuffle keys. If you want to share a cryptoshuffle key with one party but not rely on the security of a single
 * private key then split the cryptoshuffle key into two encrypted shards and someone will need to know two private keys
 * to recover the original cryptoshuffle key.
 * <p>
 * Created by Mark Grand on 6/1/2017.
 */
public class KeyShardSet {
    private static final int MINIMUM_QUORUM_SIZE = 2;
    private static final int MINIMUM_SHARD_SIZE = 8;

    private final byte[][] decryptedShards;

    @NotNull
    private final ArrayList<KeyShardGroup> groups;

    @NotNull
    private final UUID uuid;

    @NotNull
    private final AsymmetricEncryptionAlgorithm encryptionAlgorithm;

    KeyShardSet(@NotNull final ArrayList<KeyShardGroup> groups, final int shardCount,
                @NotNull final UUID uuid,
                @NotNull final AsymmetricEncryptionAlgorithm encryptionAlgorithm) {
        this.groups = groups;
        this.decryptedShards = new byte[shardCount][];
        this.uuid = uuid;
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    //TODO: Add a method that JsonUtil can call to insure that a constructed KeyShardSet is internally consistent, i.e. there are as many shards as implied by the shardCount.

    /**
     * Create a new builder for a {@code KeyShardSet}
     *
     * @param encryptionAlgorithm The algorithm that will be used to encrypt the key shards.
     * @return the new builder.
     */
    @NotNull
    public static KeyShardingSetBuilder newBuilder(@NotNull final AsymmetricEncryptionAlgorithm encryptionAlgorithm) {
        return new KeyShardingSetBuilder(encryptionAlgorithm);
    }

    @NotNull
    static byte[][] makeShards(@NotNull final byte[] cryptoshuffleKey,
                               final int requiredNumberOfShards, final int shardSize) {
        @NotNull final byte[][] shards = new byte[requiredNumberOfShards][];
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
     *
     * @return the keyShardGroups
     */
    @NotNull
    public Collection<KeyShardGroup> getGroups() {
        return groups;
    }

    public int getShardCount() {
        return decryptedShards.length;
    }

    /**
     * Return the UUID of this {@code @link KeyShardSet}
     *
     * @return the UUID.
     */
    @NotNull
    public UUID getUuid() {
        return uuid;
    }

    @NotNull
    public AsymmetricEncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * {@inheritDoc} This method ignores the presence of decrypted key shards in the object. If two {@code KeyShardSet}
     * objects have different decrypted key shards but are otherwise the same, then this method will return true.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyShardSet)) return false;

        @NotNull KeyShardSet that = (KeyShardSet) o;

        return this.getShardCount() == that.getShardCount() && groups.equals(that.groups) && uuid.equals(that.uuid);
    }

    /**
     * {@inheritDoc} This method ignores any decrypted key shards that may be in this object.
     */
    @Override
    public int hashCode() {
        int result = getShardCount();
        result = 31 * result + groups.hashCode();
        result = 31 * result + uuid.hashCode();
        return result;
    }

    /**
     * Using the given private key, decrypt any shards in this key set that are associated with the given public key.
     *
     * @param keyPair decrypt shards associated with this pair's public key using the pair's private key.
     */
    public void decryptShardsForPublicKey(@NotNull final KeyPair keyPair) {
        decryptShardsForPublicKey(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * Using the given private key, decrypt any shards in this key set that are associated with the given public key.
     *
     * @param publicKey decrypt shards associated with this public key
     * @param privateKey use the private key to decrypt.
     */
    public void decryptShardsForPublicKey(@NotNull final PublicKey publicKey, @NotNull final PrivateKey privateKey) {
        for (KeyShardGroup group : groups) {
            //noinspection CodeBlock2Expr
            group.getEncryptedShardsForKey(publicKey).forEach((position, encryptedShard) ->{
                decryptedShards[position] = encryptionAlgorithm.decrypt(privateKey, encryptedShard);
            });
        }
    }

    /**
     * Get the decrypted key.
     *
     * @return an {@link Optional} object that contains the decrypted key if all of the shards have been decrypted;
     * otherwise an empty {@link Optional} object.
     */
    @NotNull
    public Optional<byte[]> getDecryptedKey() {
        return computeDecryptedKeyLength().flatMap( length -> {
            final byte[] decryptedKey = new byte[length];
            int offset = 0;
            for (byte[] decryptedShard : decryptedShards) {
                System.arraycopy(decryptedShard, 0, decryptedKey, offset, decryptedShard.length);
            }
            return Optional.of(decryptedKey);
        });
    }

    /**
     * Compute the length of the decrypted key.
     *
     * @return An {@link Optional} object that contains the length of the decrypted key if all of the shards have been
     * decrypted; otherwise an empty {@link Optional} object.
     */
    @SuppressWarnings("WeakerAccess")
    public Optional<Integer> computeDecryptedKeyLength() {
        int length = 0;
        for (byte[] decryptedShard : decryptedShards) {
            if (decryptedShard == null) {
                return Optional.empty();
            }
            length += decryptedShard.length;
        }
        return Optional.of(length);
    }

    /**
     * Description of a group of keys that enumerates a set of public keys and the how many private keys will be needed
     * to reconstitute the original cryptoshuffle key.
     */
    public static class KeyShardGroup {
        private final int quorumSize;

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
        KeyShardGroup(final int quorumSize, @NotNull final Set<PublicKey> keys) {
            this(quorumSize, nullValuedKeyMap(keys));
        }

        KeyShardGroup(final int quorumSize, @NotNull final Map<PublicKey, Map<Integer, EncryptedShard>> keyMap) {
            if (quorumSize > keyMap.size()) {
                @NotNull final String
                        msg = "The quorum size for a group of public keys cannot be greater than the number of keys"
                                      + " which is " + keyMap.size();
                throw new IllegalArgumentException(msg);
            }
            if (quorumSize < MINIMUM_QUORUM_SIZE) {
                @NotNull final String
                        msg = "The quorum size for a group of public keys cannot be less than " + MINIMUM_QUORUM_SIZE;
                throw new IllegalArgumentException(msg);
            }
            this.quorumSize = quorumSize;
            this.keyMap = keyMap;
        }

        @NotNull
        private static Map<PublicKey, Map<Integer, EncryptedShard>> nullValuedKeyMap(@NotNull final Set<PublicKey> keys) {
            @NotNull Map<PublicKey, Map<Integer, EncryptedShard>> keyMap = new HashMap<>();
            for (PublicKey key : keys) {
                keyMap.put(key, null);
            }
            return keyMap;
        }

        /**
         * Return the minimum number of private keys that will be needed to reconstitute the full cryptoshuffle key.
         *
         * @return the minimum number of private keys that will be needed to reconstitute the full cryptoshuffle key.
         */
        public int getQuorumSize() {
            return quorumSize;
        }

        /**
         * Return the public keys in this group.
         *
         * @return a set of the public keys.
         */
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
         * Return the shards in this group associated with the specified key. The shards are returned as a Map whose
         * entries contain the shard's ordinality as the key and the shard's value as the value. If there are no shards
         * associated with the given key, an empty map is returned.
         *
         * @param key The public key to get shards for.
         * @return A map of positions to corresponding shards associated with the given public key.
         */
        @NotNull
        public Map<Integer, EncryptedShard> getEncryptedShardsForKey(@NotNull PublicKey key) {
            //noinspection unchecked
            return keyMap.getOrDefault(key, Collections.EMPTY_MAP);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof KeyShardGroup)) return false;

            @NotNull KeyShardGroup that = (KeyShardGroup) o;

            return quorumSize == that.quorumSize && keyMap.equals(that.keyMap);
        }

        @Override
        public int hashCode() {
            int result = quorumSize;
            result = 31 * result + keyMap.hashCode();
            return result;
        }
    }

    public static class KeyShardingSetBuilder {
        @NotNull
        private final ArrayList<KeyShardGroup> groups = new ArrayList<>();

        @NotNull
        private final AsymmetricEncryptionAlgorithm encryptionAlgorithm;

        @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
        @NotNull
        private final Optional<UUID> uuid = Optional.empty();

        /**
         * Constructor is private to prevent instantiation with {@code new}.
         *
         * @param encryptionAlgorithm A function that will be used to encrypt the key shards. Its first parameter should
         *                            be a public key. The second parameter should be the plain text to be encrypted.
         *                            The return value should be the encrypted text.
         */
        private KeyShardingSetBuilder(@NotNull final AsymmetricEncryptionAlgorithm encryptionAlgorithm) {
            this.encryptionAlgorithm = encryptionAlgorithm;
        }

        /**
         * Add a group of public keys to the {@code KeyShardSet} being built.
         *
         * @param quorumSize The minimum number of private keys that will be needed to reconstitute the full
         *                   cryptoshuffle key.
         * @param keys       The public keys that make up this group.
         * @return this builder.
         * @throws IllegalArgumentException If the quorumSize is less than {@value MINIMUM_QUORUM_SIZE} or greater than
         *                                  the number of keys in the group.
         */
        @NotNull
        public KeyShardingSetBuilder addKeyGroup(final int quorumSize, @NotNull final Set<PublicKey> keys) {
            groups.add(new KeyShardGroup(quorumSize, keys));
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
            for (@NotNull final KeyShardGroup group : groups) {
                @NotNull final Set<PublicKey> publicKeys = group.getKeys();
                final int quorumSize = group.getQuorumSize();
                final int groupKeyCount = publicKeys.size();
                final int shardsPerKey = (quorumSize - 1) * -1 + groupKeyCount;
                int keyIndex = 0;
                for (@NotNull final PublicKey key : publicKeys) {
                    @NotNull final Map<Integer, EncryptedShard> encryptedShardOrdinalityMapping = new HashMap<>();
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
                @NotNull final String msg = "This key set would contain " + requiredNumberOfShards + " shards."
                                                    + " The length of the key to be sharded is " + cryptoshuffleKey.length
                                                    + ". This would result in shards of length " + shardSize
                                                    + " which is less than the minimum shard size of " + MINIMUM_SHARD_SIZE;
                throw new IllegalStateException(msg);
            }
        }

        private int computeRequiredNumberOfShards() {
            int shardTotal = 0;
            for (@NotNull KeyShardGroup group : groups) {
                shardTotal += group.getKeys().size();
            }
            return shardTotal;
        }
    }
}
