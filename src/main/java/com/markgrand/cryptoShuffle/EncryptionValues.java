package com.markgrand.cryptoShuffle;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

/**
 * This generates pseudo-random values used to encrypt and decrypt.
 */
class EncryptionValues {
    private final byte lengthBias;
    private final int lengthLength;
    private final int padLength;
    private final long[][] targetIndices;
    private final int encryptedLength;

    /**
     * Constructor
     *
     * @param plaintext The plain text to be encrypted.
     * @param key       The encryption key.
     */
    EncryptionValues(final byte[] plaintext, final byte[] key) {
        DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(new SHA3Digest(512));
        digestRandomGenerator.addSeedMaterial(key);
        lengthBias = randomByte(digestRandomGenerator);
        lengthLength = significantBytes(plaintext.length);
        final int baseLength = plaintext.length + lengthLength;
        padLength = (int) (randomLong(digestRandomGenerator) % baseLength) + baseLength;
        encryptedLength = plaintext.length + lengthLength + 1 + padLength;
        targetIndices = new long[8][encryptedLength];
        computeShuffleIndices(digestRandomGenerator);
    }

    private void computeShuffleIndices(DigestRandomGenerator digestRandomGenerator) {
        for (long i = 0; i < targetIndices.length; i += 8) {
            int b = (int) (i / 8);
            targetIndices[0][b] = i;
            targetIndices[1][b] = i + 1;
            targetIndices[2][b] = i + 2;
            targetIndices[3][b] = i + 3;
            targetIndices[4][b] = i + 4;
            targetIndices[5][b] = i + 5;
            targetIndices[6][b] = i + 6;
            targetIndices[7][b] = i + 7;
        }
        long maxIndex = encryptedLength * 8 - 1;
        for (long i = 0; i < maxIndex; i++) {
            if (randomLong(digestRandomGenerator) % encryptedLength > i) {
                long temp = targetIndices[(int) (i % 8)][(int) (i / 8)];
                targetIndices[(int) (i % 8)][(int) (i / 8)] = targetIndices[7][encryptedLength - 1];
                targetIndices[7][encryptedLength - 1] = temp;
            }
        }
    }

    private int significantBytes(int n) {
        if ((n & 0xff000000) != 0)
            return 4;
        if (n > 0xffff)
            return 3;
        if (n > 0xff)
            return 2;
        return 1;
    }

    private byte randomByte(DigestRandomGenerator digestRandomGenerator) {
        byte[] b = new byte[1];
        digestRandomGenerator.nextBytes(b);
        return b[0];
    }

    private long randomLong(DigestRandomGenerator digestRandomGenerator) {
        byte[] b = new byte[8];
        digestRandomGenerator.nextBytes(b);
        return ((long) (b[0] & 0x7f) << 56) + ((long) b[1] << 48) + ((long) b[2] << 40) + ((long) b[3] << 32)
                       + ((long) b[4] << 24) + ((long) b[5] << 16) + ((long) b[6] << 8) + ((long) b[7]);
    }


    byte getLengthBias() {
        return lengthBias;
    }

    int getLengthLength() {
        return lengthLength;
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
