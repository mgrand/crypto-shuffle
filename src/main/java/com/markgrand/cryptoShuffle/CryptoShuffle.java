package com.markgrand.cryptoShuffle;

import org.jetbrains.annotations.NotNull;

import java.util.Random;

/**
 * <p>This is a symmetric encryption algorithm for use in applications like
 * protecting the secrecy of blockchain contents where the encryption needs
 * to be very strong. The algorithm should have these properties:</p>
 * <ul>
 * <li>Longer encrypted texts require more effort to crack than shorter texts.</li>
 * <li>It is necessary to decrypt the entire text at once, rather than decrypt in pieces as with a block cypher.</li>
 * <li>There is no upper limit on the key length.</li>
 * <li>One of the challenges of cracking the encryption is that there will be multiple solutions that look reasonable
 * and no clue as to which is correct.</li>
 * </ul>
 * <p>
 * The algorithm implemented in this package is based on doing a random
 * shuffle of the ones and zeros in a plaintext. The actual order of the
 * shuffle is based on the encryption key.</p>
 * <p>
 * Here is a high-level description of the encryption algorithm based on
 * the bouncycastle library:</p>
 * <ol>
 * <li>Inputs to the algorithm are a plaintext message that is a sequence of
 * bytes and a key that is an arbitrary sequence of bytes.<br><br></li>
 * <li>Compute a SHA512 hash of the key.<br><br></li>
 * <li>The purpose of this step is to add random extraneous bits to ensure
 * that a brute force attempt to decrypt the encrypted text will result
 * in multiple candidates for the plaintext that will be wrong but
 * appear to be a reasonable solution.<br><br></li>
 * <li>Using a separate random number that is in no way dependent on the key
 * we are using, append random bytes to the plaintext to double the
 * length of the plaintext.
 * <p>Use the hash as the seed for a pseudo-random sequence of numbers. The
 * following steps will be based on this sequence. The decryption
 * operation will consist of performing the following steps in reverse
 * using the same sequence of pseudo-random numbers.
 * <p>For interoperability, all implementations of this encryption
 * algorithm will need to use the same pseudo-random number generator.
 * The DigestRandomGenerator class from the Bouncycastle library is used
 * for this purpose. There is a paper that includes an analysis of this
 * pseudo-random number generator at
 * <a href="https://www.hgi.rub.de/media/nds/veroeffentlichungen/2013/03/25/paper_2.pdf">https://www.hgi.rub.de/media/nds/veroeffentlichungen/2013/03/25/paper_2.pdf</a>.
 * <br><br></li>
 * <li>Perform a shuffle of the plaintext based on pseudo-random numbers.</li>
 * </ol>
 * There is a wrinkle to the algorithm that is not mentioned above. The
 * pseudo-random numbers are generated from a SHA512 has of the key. This
 * is a 512 bit hash value. If we use the entire key to compute the the
 * hash value and then compute the pseudo-random numbers, then no matter
 * how long the given encryption key is, the effective length of the key is
 * limited 512 bits.
 * <p>
 * While 512 bits is a respectable key size, limiting the effective key
 * length to 512 bits is a problem. The problem is that it weakens the goal
 * of this algorithm being harder to crack for longer texts.
 * <p>
 * The number of possible shuffles of the bits in a long plaintext is
 * limited by the effective key length. If it were the case that the
 * effective key length was limited to 512 bits, then there would be
 * shuffles of longer plain texts that could be ruled out as not being
 * possible to generate from an 512 bit key. For this reason, the way that
 * we use the key is modified for long keys with long plain texts, so that
 * the effective length of the key is as unlimited as the given keys.
 * <p>
 * If the key is longer than 256 bytes and the plaintext is longer than 128
 * bytes then the algorithm uses the key in a more elaborate way.
 * <p>
 * The plaintext is divided into groups of 64 bytes with the possibility of
 * the last group being less than 64 bytes. The key is divided into groups
 * of 128 bytes with the possibility of the last group being less than 128
 * bytes.
 * <p>
 * If this yields an equal number of key and plaintext groups, then this is
 * how the key is used: The SHA512 hash for the first key group is computed
 * and then used as the seed to generate pseudo-random numbers that determine
 * the shuffle destination of the bits in the first plaintext group. The
 * second key group is then combined with the current seed value to produce
 * a new SHA512 hash. This new hash is used as the seed to generate
 * pseudo-random numbers that determine the shuffle destination of the bits
 * in the second plaintext group. This procedure continues to the end of
 * the groups.
 * <p>
 * If there are fewer key groups than plaintext groups, then after the last
 * key group has been incorporated into the seed value that seed is used to
 * generate pseudo-random numbers for the rest of the groups in the plaintext.
 * If there are more key groups than plaintext groups, then the size of the
 * key groups is increased so that the number of key groups will be equal
 * to the number of plaintext groups.
 * <p>
 * As mentioned above, the encryption algorithm is implemented using the
 * Bouncycastle library. This implementation of Crypto-Shuffle is written
 * in Java. There is a C# implementation of the Bouncycastle library, so
 * perhaps there will be a C# implementation of Crypto-Shuffle.
 * @author Mark Grand
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class CryptoShuffle {
    private static final byte VERSION_ONE = 0x01;
    /**
     * A constant to indicate the number of initial bytes in the encrypted array that contain the version number
     * of this class.
     */
    public static final int VERSION_OFFSET = 1;

    /**
     * Encrypt the given plaintext using the given key.
     *
     * @param plaintext The plain text to be encrypted.
     * @param key       The encryption key.
     * @return The encrypted version of the plaintext.
     */
    @NotNull
    public static byte[] encrypt(@NotNull final byte[] plaintext, @NotNull final byte[] key) {
        @NotNull final EncryptionValues ev = EncryptionValues.forEncryption(plaintext, key);
        @NotNull final byte[] workingStorage = new byte[ev.getEncryptedLength()];
        System.arraycopy(plaintext, 0, workingStorage, 0, plaintext.length);
        @NotNull final Random r = new Random();
        final int paddingOffset = plaintext.length;
        generateRandomPaddingBytes(workingStorage, paddingOffset, ev.getPadLength(), r);
        @NotNull final byte[] encrypted = shuffle(workingStorage, ev);
        encrypted[0] = VERSION_ONE;
        return encrypted;
    }

    @NotNull
    public static byte[] decrypt(@NotNull final byte[] encrypted, @NotNull final byte[] key) {
        switch (encrypted[0]) {
            case VERSION_ONE:
                return decryptV1(encrypted, key);
        }
        @NotNull String msg = "Encrypted bytes were encrypted with an unsupported version:";
        throw new IllegalArgumentException(msg + (int) encrypted[0]);
    }

    @NotNull
    private static byte[] decryptV1(@NotNull final byte[] encrypted, @NotNull final byte[] key) {
        @NotNull EncryptionValues ev = EncryptionValues.forDecryption(encrypted, key);
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
    @NotNull
    static byte[] shuffle(@NotNull byte[] workingStorage, @NotNull EncryptionValues ev) {
        @NotNull byte[] encrypted = new byte[workingStorage.length + VERSION_OFFSET];
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

    @NotNull
    private static byte[] reverseShuffle(@NotNull final byte[] encrypted, @NotNull final EncryptionValues ev) {
        final int plaintextLength = (encrypted.length - VERSION_OFFSET) / 2;
        @NotNull final byte[] plaintext = new byte[plaintextLength];
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

    private static void generateRandomPaddingBytes(@NotNull final byte[] workingStorage,
                                                   final int offset,
                                                   final int padLength,
                                                   @NotNull final Random r) {
        @NotNull final byte[] buffer = new byte[padLength];
        r.nextBytes(buffer);
        System.arraycopy(buffer, 0, workingStorage, offset, padLength);
    }
}
