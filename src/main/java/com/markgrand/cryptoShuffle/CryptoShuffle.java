package com.markgrand.cryptoShuffle;

import java.util.Random;

/**
 * <p>Implements a highly secure algorithm with the following properties:</p>
 * <ul>
 * <li>Longer encrypted texts should require more effort to crack than shorter texts.</li>
 * <li>It should be necessary to decrypt the entire text at once, rather than  being possible to decrypt in pieces
 * as with a block cypher.</li>
 * <li>There should be no upper limit on the key length.</li>
 * <li>One of the challenges of cracking the encryption should be that there
 * will be multiple possible solutions that look reasonable and no clue
 * as to which is correct.</li>
 * </ul>
 * <p>The algorithm implemented in this package is based on doing a random shuffle of the ones and zeros in a plaintext.
 * The actual order of the shuffle is based on the encryption key.</p>
 * <p>Here is a high-level description of the algorithm:</p>
 * <ol>
 * <li>Inputs to the algorithm are a plaintext message that is a sequence of bytes and a key that is an
 * arbitrary sequence of bytes.</li>
 * <li>Compute a SHA3-512 hash of the key.</li>
 * <li>Use the hash as the seed for a pseudo-random sequence of numbers. The
 * following steps will be based on this sequence. The decryption
 * operation will consist of performing the following steps in reverse
 * using the same sequence of pseudo-random numbers.
 * <p>For interoperability, all implementations of this encryption
 * algorithm will need to use the same pseudo-random number generator.
 * The DigestRandomGenerator class from the Bouncycastle library is used
 * for this purpose. There is a <a href="https://www.hgi.rub.de/media/nds/veroeffentlichungen/2013/03/25/paper_2.pdf">
 * paper that includes an analysis of this pseudo-random number generator.</a></p></li>
 * <li>Append to the plaintext bytes containing the length of the plaintext
 * as an unsigned binary integer. For consistency, the bytes should be
 * appended in big-endian order (most significant byte first, least
 * significant byte last). The length of the integer should be the
 * minimum number of bytes needed to represent the value.
 * <p>The reason for not using a fixed number of bytes to represent the
 * length is to avoid having a high-order byte that is likely to be zero
 * and thereby provide a clue as to location of the length value.</p></li>
 * <li>Append a byte to the plaintext that contains the number of bytes
 * appended to the plaintext in the previous step.  The actual value
 * stored in this byte should be the sum of the number of bytes plus a
 * random value, ignoring overflow. The reason for adding the random
 * number is to avoid having a predictable value in this position.</li>
 * <li>This step has two purposes. Firstly we want to avoid giving any clue
 * about the plaintext from the relative number of ones and zeros in the
 * encrypted message. Secondly, we want to add extraneous bits to ensure
 * that a brute force attempt to decrypt the encrypted text will result
 * in multiple candidates for the plaintext that will be wrong but
 * appear to be a reasonable solution.
 * <p>
 * <p>Compute a random number r that is between _n_ and _2n_, where _n_ is
 * the current length of the plaintext. Using a separate random number
 * generator that is independent of the one we are using for every other
 * step, append _r_ random bytes to the plaintext. If the total number
 * of ones and zeros in the plaintext is not equal, then using the same
 * independent pseudo random number generator, invert randomly selected
 * bits in the appended bytes until the number of ones and zeros in the
 * plaintext is equal.</p></li>
 * <li>Perform a shuffle of the plaintext based on pseudo-random numbers.</li>
 * </ol>
 *
 * @author Mark Grand
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class CryptoShuffle {
    private static final byte VERSION_ONE = 0x01;

    /**
     * Encrypt the given plaintext using the given key.
     *
     * @param plaintext The plain text to be encrypted.
     * @param key       The encryption key.
     * @return The encrypted version of the plaintext.
     */
    public static byte[] encrypt(final byte[] plaintext, final byte[] key) {
        final EncryptionValues ev = new EncryptionValues(plaintext, key);
        final byte[] workingStorage = new byte[ev.getEncryptedLength()];
        System.arraycopy(plaintext, 0, workingStorage, 0, plaintext.length);
        storeLength(workingStorage, plaintext.length, ev.getLengthLength());
        workingStorage[plaintext.length + ev.getLengthLength()] = (byte) (ev.getLengthLength() + ev.getLengthBias());
        final Random r = new Random();
        final int paddingOffset = plaintext.length + ev.getLengthLength();
        generateRandomPaddingBytes(workingStorage, paddingOffset, ev.getPadLength(), r);
        balanceOnesAndZeros(workingStorage, paddingOffset, ev.getPadLength(), r);
        return shuffle(workingStorage, ev);
    }

    private static byte[] shuffle(byte[] workingStorage, EncryptionValues ev) {
        byte[] encrypted = new byte[workingStorage.length +1];
        long[][] indices = ev.getTargetIndices();
        encrypted[0] = VERSION_ONE;
        for (int i = 0; i < workingStorage.length; i++) {
            for (int b = 0; b < 8; b++) {
                long compoundIndex = indices[b][i];
                int index = (int) (compoundIndex / 8);
                int bit = (int) (compoundIndex % 8);
                int mask = 1 << bit;
                encrypted[index] |= (workingStorage[i] & mask);
            }
        }
        return encrypted;
    }

    private static void balanceOnesAndZeros(final byte[] workingStorage,
                                            final int paddingOffset,
                                            final int padLength,
                                            final Random r) {
        final int onesCount = ByteUtil.countOnes(workingStorage, 0, workingStorage.length);
        final int zerosCount = (workingStorage.length - 1) * 8 - onesCount;
        int difference = onesCount - zerosCount;
        int bitTarget = (difference >0) ? 0 : 1;
        while (difference != 0) {
            int index = (int) (r.nextLong() % padLength) + paddingOffset;
            int bit = r.nextInt() & 7;
            if (((workingStorage[index]>>bit) & 1) == bitTarget) {
                int mask = 1 << bit;
                if (bitTarget == 1) {
                    workingStorage[index] &= ~mask;
                } else {
                    workingStorage[index] |= mask;
                }
            }
        }
    }

    private static void generateRandomPaddingBytes(final byte[] workingStorage,
                                                   final int offset,
                                                   final int padLength,
                                                   final Random r) {
        final byte[] buffer = new byte[padLength];
        r.nextBytes(buffer);
        System.arraycopy(buffer, 0, workingStorage, offset, padLength);
    }

    private static void storeLength(final byte[] workingStorage, final int length, final int lengthLength) {
        assert lengthLength <= 4 && lengthLength >= 1;
        int offset = length + 1;
        switch (lengthLength) {
            case 4:
                workingStorage[offset] = (byte) (length >>> 24);
                offset += 1;
            case 3:
                workingStorage[offset] = (byte) (length >>> 16);
                offset += 1;
            case 2:
                workingStorage[offset] = (byte) (length >>> 8);
                offset += 1;
            case 1:
                workingStorage[offset] = (byte) length;
        }
    }

}
