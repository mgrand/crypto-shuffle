package com.markgrand.cryptoShuffle;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

/**
 * This generates pseudo-random values used to encrypt and decrypt.
 */
class EncryptionValues {
    /**
     * Maximum supported length for plaintext.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int MAX_LENGTH = Integer.MAX_VALUE / 2;

    private int padLength;
    private long[][] targetIndices;
    private int encryptedLength;

    /**
     * Compute values needed to encrypt.
     *
     * @param plaintext The plain text to be encrypted.
     * @param key       The encryption key.
     * @throws IllegalArgumentException if the length of plaintext is greater than {@value MAX_LENGTH}.
     */
    @NotNull
    static EncryptionValues forEncryption(@NotNull final byte[] plaintext, @NotNull final byte[] key) {
        if (plaintext.length > MAX_LENGTH) {
            throw new IllegalArgumentException("Plaintext is longer than maximum supported length of " + MAX_LENGTH);
        }
        @NotNull EncryptionValues ev = new EncryptionValues();
        ev.padLength = plaintext.length;
        ev.encryptedLength = plaintext.length + ev.padLength;
        ev.targetIndices = new long[8][ev.encryptedLength];
        @NotNull DigestRandomGenerator digestRandomGenerator = createDigestRandomGenerator();
        int keyConsumptionIncrement = computeKeyConsumptionIncrement(key.length, plaintext.length);
        ev.computeShuffleIndices(digestRandomGenerator, keyConsumptionIncrement, key);
        return ev;
    }

    private static DigestRandomGenerator createDigestRandomGenerator() {
        return new DigestRandomGenerator(new SHA512Digest());
    }

    /**
     * Compute values needed to decrypt.
     *
     * @param encrypted The encrypted text to be decrypted.
     * @param key       The encryption key.
     */
    @NotNull
    static EncryptionValues forDecryption(@NotNull final byte[] encrypted, @NotNull final byte[] key) {
        @NotNull EncryptionValues ev = new EncryptionValues();
        ev.encryptedLength = encrypted.length - 1;
        ev.padLength = encrypted.length / 2;
        ev.targetIndices = new long[8][ev.encryptedLength];
        @NotNull DigestRandomGenerator digestRandomGenerator = createDigestRandomGenerator();
        int keyConsumptionIncrement = computeKeyConsumptionIncrement(key.length, encrypted.length / 2);
        ev.computeShuffleIndices(digestRandomGenerator, keyConsumptionIncrement, key);
        return ev;
    }

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private EncryptionValues() {
    }

    /**
     * If the key is longer than 256 bytes and the plaintext is longer than 128
     * bytes then the algorithm uses the key in a more elaborate way.
     * <p/>
     * The plaintext is divided into groups of 64 bytes with the possibility of
     * the last group being less than 64 bytes. The key is divided into groups
     * of 128 bytes with the possibility of the last group being less than 128
     * bytes.
     * <p/>
     * If this yields an equal number of key and plaintext groups, then this is
     * how the key is used: The SHA512 hash for the first key group is computed
     * and then used as the seed to generate pseudo-random numbers that determine
     * the shuffle destination of the bits in the first plaintext group. The
     * second key group is then combined with the current seed value to produce
     * a new SHA512 hash. This new hash is used as the seed to generate
     * pseudo-random numbers that determine the shuffle destination of the bits
     * in the second plaintext group. This procedure continues to the end of
     * the groups.
     * <p/>
     * If there are fewer key groups than plaintext groups, then after the last
     * key group has been incorporated into the seed value that seed is used to
     * generate pseudo-random numbers for the rest of the groups in the plaintext.
     * If there are more key groups than plaintext groups, then the size of the
     * key groups is increased so that the number of key groups will be equal
     * to the number of plaintext groups.
     *
     * @param keyLength       The length of the key in bytes.
     * @param plainTextLength The length of the plain text in bytes.
     * @return the number of bytes of the key that should be used to seed the {@link DigestRandomGenerator} when
     * computing shuffle indices for each group of 64 bytes of the plain text. This may be a value that causes the key
     * to be exhausted before all of the shuffle indices are computed.
     */
    private static int computeKeyConsumptionIncrement(final int keyLength, final int plainTextLength) {
        if (keyLength <= 256 || plainTextLength <= 128) {
            return keyLength;
        }
        final int plainTextGroupCount = (int) (((long) plainTextLength + 63L) / 64);
        int keyConsumptionIncrement = keyLength / plainTextGroupCount;
        if (keyConsumptionIncrement * plainTextGroupCount < keyLength) {
            keyConsumptionIncrement += 1;
        }
        return keyConsumptionIncrement;
    }

    private void computeShuffleIndices(@NotNull final DigestRandomGenerator digestRandomGenerator,
                                       final int keyConsumptionIncrement,
                                       @NotNull final byte[] key) {
        int keyBytesConsumed = 0;
        final int maxIndex = encryptedLength * 8;
        @NotNull final byte[] randomByteBuffer = new byte[8];
        for (long i = 0; i < maxIndex; i++) {
            if (0 == i % keyConsumptionIncrement) {
                keyBytesConsumed = consumeKeyBytes(digestRandomGenerator, keyBytesConsumed, keyConsumptionIncrement, key);
            }
            digestRandomGenerator.nextBytes(randomByteBuffer);
            long randomIndex = bytesToLong(randomByteBuffer) % (i + 1);
            if (randomIndex != i) {
                targetIndices[(int) (i % 8)][(int) (i / 8)] = targetIndices[(int) (randomIndex % 8)][(int) (randomIndex / 8)];
            }
            targetIndices[(int) (randomIndex % 8)][(int) (randomIndex / 8)] = i;
        }
    }

    private int consumeKeyBytes(@NotNull final DigestRandomGenerator digestRandomGenerator, final int keyBytesConsumed,
                                final int keyConsumptionIncrement, @NotNull final byte[] key) {
        final int keyBytesRemaining = key.length - keyBytesConsumed;
        if (keyBytesRemaining > 0) {
            int bytesToConsume = (keyBytesRemaining > keyConsumptionIncrement) ? keyConsumptionIncrement : keyBytesRemaining;
            @NotNull byte[] keyBuffer = new byte[bytesToConsume];
            System.arraycopy(key, keyBytesConsumed, keyBuffer, 0, bytesToConsume);
            digestRandomGenerator.addSeedMaterial(keyBuffer);
            return keyBytesConsumed + bytesToConsume;
        }
        return keyBytesConsumed;
    }

    private long bytesToLong(byte[] bytes) {
        return ((long) (bytes[0] & 0x7f) << 56)
                       | ((long) (bytes[1] & 0xff) << 48)
                       | ((long) (bytes[2] & 0xff) << 40)
                       | ((long) (bytes[3] & 0xff) << 32)
                       | ((long) (bytes[4] & 0xff) << 24)
                       | ((long) (bytes[5] & 0xff) << 16)
                       | ((long) (bytes[6] & 0xff) << 8)
                       | ((long) (bytes[7] & 0xff));
    }


    int getPadLength() {
        return padLength;
    }

    long[][] getTargetIndices() {
        return targetIndices;
    }

    int getEncryptedLength() {
        return encryptedLength;
    }

    @NotNull
    @Override
    public String toString() {
        @NotNull final StringBuilder builder = new StringBuilder();
        builder.append("EncryptionValues{padLength=").append(padLength)
                .append(", encryptedLength=").append(encryptedLength).append(", targetIndices=");
        for (int b = 0; b < targetIndices.length; b++) {
            builder.append("\n[").append(b).append(']').append(Arrays.toString(targetIndices[b]));
        }
        builder.append('}');
        return builder.toString();
    }
}
