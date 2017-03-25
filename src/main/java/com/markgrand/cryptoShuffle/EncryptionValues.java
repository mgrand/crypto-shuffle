package com.markgrand.cryptoShuffle;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

/**
 * This generates pseudo-random values used to encrypt and decrypt.
 */
class EncryptionValues {
    /**
     * Maximum supported length for plaintext.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int MAX_LENGTH = Integer.MAX_VALUE / 2;

    private final int padLength;
    private final long[][] targetIndices;
    private final int encryptedLength;

    /**
     * Constructor
     *
     * @param plaintext The plain text to be encrypted.
     * @param key       The encryption key.
     * @throws IllegalArgumentException if the length of plaintext is greater than {@value MAX_LENGTH}.
     */
    EncryptionValues(final byte[] plaintext, final byte[] key) {
        if (plaintext.length > MAX_LENGTH) {
            throw new IllegalArgumentException("Plaintext is longer than maximum supported length of " + MAX_LENGTH);
        }
        DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(new SHA3Digest(512));
        digestRandomGenerator.addSeedMaterial(key);
        padLength = plaintext.length;
        encryptedLength = plaintext.length + padLength;
        targetIndices = new long[8][encryptedLength];
        computeShuffleIndices(digestRandomGenerator);
    }

    private void computeShuffleIndices(DigestRandomGenerator digestRandomGenerator) {
        long maxIndex = encryptedLength * 8 - 1;
        for (long i = 0; i < maxIndex; i++) {
            long randomIndex = randomPositiveLong(digestRandomGenerator) % (i + 1);
            if (randomIndex != i) {
                targetIndices[(int) (i % 8)][(int) (i / 8)] = targetIndices[(int) (randomIndex % 8)][(int) (randomIndex / 8)];
            }
            targetIndices[(int) (randomIndex % 8)][(int) (randomIndex / 8)] = i;
        }
    }

    private long randomPositiveLong(DigestRandomGenerator digestRandomGenerator) {
        byte[] b = new byte[8];
        digestRandomGenerator.nextBytes(b);
        return ((long) (b[0] & 0x7f) << 56)
                       | ((long) (b[1] & 0xff) << 48)
                       | ((long) (b[2] & 0xff) << 40)
                       | ((long) (b[3] & 0xff) << 32)
                       | ((long) (b[4] & 0xff) << 24)
                       | ((long) (b[5] & 0xff) << 16)
                       | ((long) (b[6] & 0xff) << 8)
                       | ((long) (b[7] & 0xff));
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
}
