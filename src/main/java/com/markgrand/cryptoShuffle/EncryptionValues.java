package com.markgrand.cryptoShuffle;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

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
    static EncryptionValues forEncryption(final byte[] plaintext, final byte[] key) {
        if (plaintext.length > MAX_LENGTH) {
            throw new IllegalArgumentException("Plaintext is longer than maximum supported length of " + MAX_LENGTH);
        }
        EncryptionValues ev = new EncryptionValues();
        ev.padLength = plaintext.length;
        ev.encryptedLength = plaintext.length + ev.padLength;
        ev.targetIndices = new long[8][ev.encryptedLength];
        DigestRandomGenerator digestRandomGenerator = createDigestRandomGenerator(key);
        int keyConsumptionIncrement = computeKeyConsumptionIncrement(key.length, plaintext.length);
        ev.computeShuffleIndices(digestRandomGenerator);
        return ev;
    }

    private static DigestRandomGenerator createDigestRandomGenerator(byte[] key) {
        DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(new SHA512Digest());
        digestRandomGenerator.addSeedMaterial(key);
        return digestRandomGenerator;
    }

    /**
     * Compute values needed to decrypt.
     *
     * @param encrypted The encrypted text to be decrypted.
     * @param key       The encryption key.
     */
    static EncryptionValues forDecryption(final byte[] encrypted, final byte[] key) {
        EncryptionValues ev = new EncryptionValues();
        ev.encryptedLength = encrypted.length - 1;
        ev.padLength = encrypted.length / 2;
        ev.targetIndices = new long[8][ev.encryptedLength];
        DigestRandomGenerator digestRandomGenerator = createDigestRandomGenerator(key);
        int keyConsumptionIncrement = computeKeyConsumptionIncrement(key.length, encrypted.length/2);
        ev.computeShuffleIndices(digestRandomGenerator);
        return ev;
    }

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
     * @param keyLength The length of the key in bytes.
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

    private void computeShuffleIndices(final DigestRandomGenerator digestRandomGenerator) {
        final int maxIndex = encryptedLength * 8;
        final byte[] randomByteBuffer = new byte[8 * 8];
        for (long i = 0; i < maxIndex; i++) {
            digestRandomGenerator.nextBytes(randomByteBuffer);
            long randomIndex = bytesToLong(randomByteBuffer, (int) (i % 8)) % (i + 1);
            if (randomIndex != i) {
                targetIndices[(int) (i % 8)][(int) (i / 8)] = targetIndices[(int) (randomIndex % 8)][(int) (randomIndex / 8)];
            }
            targetIndices[(int) (randomIndex % 8)][(int) (randomIndex / 8)] = i;
        }
    }

    private long bytesToLong(byte[] bytes, int offset) {
        int j = offset * 8;
        return ((long) (bytes[j] & 0x7f) << 56)
                       | ((long) (bytes[j + 1] & 0xff) << 48)
                       | ((long) (bytes[j + 2] & 0xff) << 40)
                       | ((long) (bytes[j + 3] & 0xff) << 32)
                       | ((long) (bytes[j + 4] & 0xff) << 24)
                       | ((long) (bytes[j + 5] & 0xff) << 16)
                       | ((long) (bytes[j + 6] & 0xff) << 8)
                       | ((long) (bytes[j + 7] & 0xff));
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

    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("EncryptionValues{padLength=").append(padLength)
                .append(", encryptedLength=").append(encryptedLength).append(", targetIndices=");
        for (int b = 0; b < targetIndices.length; b++) {
            builder.append("\n[").append(b).append(']').append(Arrays.toString(targetIndices[b]));
        }
        builder.append('}');
        return builder.toString();
    }
}
