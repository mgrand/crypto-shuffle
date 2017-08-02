package com.markgrand.cryptoShuffle.keyShard;

/**
 * <p>Value object to contain the details of an encrypted key shard.
 * </p>
 * Created by mark.grand on 7/16/2017.
 */
public class EncryptedShard {
    private final byte[] encodedPublicKey;
    private final byte[] encryptedShardValue;
    private final SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm;
    private final byte[] encryptedSymmetricKey;

    /**
     * Create an encrypted shard that is encrypted by directly applying an
     * asymmetric encryption algorithm to the shard.
     *
     * @param encodedPublicKey The public key used to encrypt the shard.
     * @param encryptedShard   The encrypted shard value.
     */
    public EncryptedShard(final byte[] encodedPublicKey, final byte[] encryptedShard) {
        this(encodedPublicKey, encryptedShard, null, null);
    }


    /**
     * Create an encrypted shard that is encrypted by indirectly generating a
     * key for a symmetric encryption algorithm, encrypting the shard with the
     * symmetric algorithm using the generated key and then encrypting the
     * generated key with the public key.
     *
     * @param encodedPublicKey             The public key used to encrypt the symmetric key.
     * @param encryptedShardValue               The encrypted shard value.
     * @param symmetricEncryptionAlgorithm The symmetric encryption algorithm
     *                                     used to encrypt the shard value.
     * @param encryptedSymmetricKey        The encrypted symmetric key.
     */
    public EncryptedShard(final byte[] encodedPublicKey,
                          final byte[] encryptedShardValue,
                          final SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm,
                          final byte[] encryptedSymmetricKey) {
        this.encodedPublicKey = encodedPublicKey;
        this.encryptedShardValue = encryptedShardValue;
        this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
    }

    /**
     * Return the encoding of the public key used to encrypt this shard.
     */
    public byte[] getEncodedPublicKey() {
        return encodedPublicKey;
    }

    /**
     * Return the encrypted value of this shard.
     */
    public byte[] getEncryptedShardValue() {
        return encryptedShardValue;
    }

    /**
     * Return the symmetric encryption algorithm that was used to encrypt the
     * shard value or null.
     */
    public SymmetricEncryptionAlgorithm getSymmetricEncryptionAlgorithm() {
        return symmetricEncryptionAlgorithm;
    }

    /**
     * Return the encrypted value of the symmetric key used to encrypt the
     * shard value or null.
     */
    public byte[] getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }
}
