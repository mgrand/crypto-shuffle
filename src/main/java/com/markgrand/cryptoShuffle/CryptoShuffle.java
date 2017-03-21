package com.markgrand.cryptoShuffle;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

/**
 * <p>Implements a highly secure algorithm with the following properties:</p>
 * <ul>
 * <li>Longer encrypted texts should require more effort to crack than shorter texts.</li>
 * <li>It should be necessary to decrypt the entire text at once, rather than  being possible to decrypt in pieces
 * as with a block chypher.</li>
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
 */
@SuppressWarnings("unused")
public class CryptoShuffle {
    /**
     * Encrypt the given plaintext using the given key.
     *
     * @param plaintext The plain text to be encrypted.
     * @param key       The encryption key.
     * @return The encrypted version of the plaintext.
     */
    public static byte[] encrypt(final byte[] plaintext, final byte[] key) {
        final EncryptionValues ev = new EncryptionValues(plaintext, key);

        return new byte[0];
    }

    /**
     * This generates pseudo-random values used to encrypt and decrypt.
     */
    private static class EncryptionValues {
        private final byte lengthOffset;
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
        private EncryptionValues(final byte[] plaintext, final byte[] key) {
            DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(new SHA3Digest(512));
            digestRandomGenerator.addSeedMaterial(key);
            lengthOffset = randomByte(digestRandomGenerator);
            lengthLength = significantBytes(plaintext.length);
            final int baseLength = plaintext.length + lengthLength;
            padLength = (int) (randomLong(digestRandomGenerator) % baseLength) + baseLength;
            encryptedLength = plaintext.length + padLength + lengthLength + 1;
            targetIndices = new long[encryptedLength][8];
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
                    long temp = targetIndices[(int)(i%8)][(int)(i/8)];
                    targetIndices[(int)(i%8)][(int)(i/8)] = targetIndices[7][encryptedLength - 1];
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
    }
}
