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
     * A constant to indicate the number of initial bytes in the encrypted array that contain the version number
     * of this class.
     */
    public static int VERSION_OFFSET = 1;

    /**
     * Encrypt the given plaintext using the given key.
     *
     * @param plaintext The plain text to be encrypted.
     * @param key       The encryption key.
     * @return The encrypted version of the plaintext.
     */
    public static byte[] encrypt(final byte[] plaintext, final byte[] key) {
        final EncryptionValues ev = EncryptionValues.forEncryption(plaintext, key);
        final byte[] workingStorage = new byte[ev.getEncryptedLength()];
        System.arraycopy(plaintext, 0, workingStorage, 0, plaintext.length);
        final Random r = new Random();
        final int paddingOffset = plaintext.length;
        generateRandomPaddingBytes(workingStorage, paddingOffset, ev.getPadLength(), r);
        final byte[] encrypted = shuffle(workingStorage, ev);
        encrypted[0] = VERSION_ONE;
        return encrypted;
    }

    public static byte[] decrypt(final byte[] encrypted, final byte[] key) {
        switch (encrypted[0]) {
            case VERSION_ONE:
                return decryptV1(encrypted, key);
        }
        String msg = "Encrypted bytes were encrypted with an unsupported version:";
        throw new IllegalArgumentException(msg + (int) encrypted[0]);
    }

    private static byte[] decryptV1(final byte[] encrypted, final byte[] key) {
        EncryptionValues ev = EncryptionValues.forDecryption(encrypted, key);
        return reverseShuffle(encrypted, ev);
    }

    /**
     * Create an Array that contains the bits from {@code workingStorage} shuffled into the order specified by
     * the {@code ev} object's {@link EncryptionValues#getTargetIndices()} method.
     *
     * @param workingStorage The array of bits to be shuffled.
     * @param ev             An object that specifies the shuffle order.
     * @return An array where the first {@link #VERSION_OFFSET} bytes contain the version number of this class and the
     * following bytes contain the shuffled bits.
     */
    static byte[] shuffle(byte[] workingStorage, EncryptionValues ev) {
        byte[] encrypted = new byte[workingStorage.length + VERSION_OFFSET];
        long[][] indices = ev.getTargetIndices();
        for (int i = 0; i < workingStorage.length; i++) {
            for (int b = 0; b < 8; b++) {
                long compoundIndex = indices[b][i];
                int index = (int) (compoundIndex / 8);
                int bit = (int) (compoundIndex % 8);
                int bitValue = (workingStorage[i] & (1 << b));
                if (bitValue != 0) {
                    encrypted[index + VERSION_OFFSET] |= 1 << bit;
                }
            }
        }
        return encrypted;
    }

    private static byte[] reverseShuffle(final byte[] encrypted, final EncryptionValues ev) {
        final int plaintextLength = (encrypted.length - VERSION_OFFSET) / 2;
        final byte[] plaintext = new byte[plaintextLength];
        final long[][] indices = ev.getTargetIndices();
        for (int i = 0; i < plaintextLength; i++) {
            for (int b = 0; b < 8; b++) {
                long compoundIndex = indices[b][i];
                int index = (int) (compoundIndex / 8);
                int bit = (int) (compoundIndex % 8);
                int bitValue = (encrypted[index + VERSION_OFFSET] & (1 << bit));
                if (bitValue != 0) {
                    plaintext[i] |= 1 << b;
                }
            }
        }
        return plaintext;
    }

    private static void generateRandomPaddingBytes(final byte[] workingStorage,
                                                   final int offset,
                                                   final int padLength,
                                                   final Random r) {
        final byte[] buffer = new byte[padLength];
        r.nextBytes(buffer);
        System.arraycopy(buffer, 0, workingStorage, offset, padLength);
    }
}
