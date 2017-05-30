# crypto-shuffle 0.5

This is a symmetric encryption algorithm for use in applications like
protecting the secrecy of blockchain contents where the encryption needs
to be very strong. The algorithm should has these properties:

* Longer encrypted   texts require more effort to crack than shorter
  texts.
* It is necessary to decrypt the entire text at once, rather than
  decrypt in pieces as with a block cypher.
* There is no upper limit on the key length.
* One of the challenges of cracking the encryption is that there will be
  multiple solutions that look reasonable and no clue as to which is
  correct.

The algorithm implemented in this package is based on doing a random
shuffle of the ones and zeros in a plaintext. The actual order of the
shuffle is based on the encryption key.

Here is a high-level description of the encryption algorithm based on
the bouncycastle library:

1. Inputs to the algorithm are a plaintext message that is a sequence of
   bytes and a key that is an arbitrary sequence of bytes.

2. Compute a SHA512 hash of the key.

3. The purpose of this step is to add random extraneous bits to ensure
   that a brute force attempt to decrypt the encrypted text will result
   in multiple candidates for the plaintext that will be wrong but
   appear to be a reasonable solution.

   Using a separate random number that is in no way dependent on the key
   we are using, append random bytes to the plaintext to double the
   length of the plaintext.

4. Use the hash as the seed for a pseudo-random sequence of numbers. The
   following steps will be based on this sequence. The decryption
   operation will consist of performing the following steps in reverse
   using the same sequence of pseudo-random numbers.

   For interoperability, all implementations of this encryption
   algorithm will need to use the same pseudo-random number generator.
   The DigestRandomGenerator class from the Bouncycastle library is used
   for this purpose. There is a paper that includes an analysis of this
   pseudo-random number generator at
   https://www.hgi.rub.de/media/nds/veroeffentlichungen/2013/03/25/paper_2.pdf.

5. Perform a shuffle of the plaintext based on pseudo-random numbers.

There is a wrinkle to the algorithm that is not mentioned above. The
pseudo-random numbers are generated from a SHA512 has of the key. This
is a 512 bit hash value. If we use the entire key to compute the the
hash value and then compute the pseudo-random numbers, then no matter
how long the given encryption key is, the effective length of the key is
limited 512 bits.

While 512 bits is a respectable key size, limiting the effective key
length to 512 bits is a problem. The problem is that it weakens the goal
of this algorithm being harder to crack for longer texts.

The number of possible shuffles of the bits in a long plaintext is
limited by the effective key length. If it were the case that the
effective key length was limited to 512 bits, then there would be
shuffles of longer plaintexts that could be ruled out as not being
possible to generate from an 512 bit key. For this reason, the way that
we use the key is modified for long keys with long plaintexts, so that
the effective length of the key is as unlimited as the given keys.

If the key is longer than 256 bytes and the plaintext is longer than 128
bytes then the algorithm uses the key in a more elaborate way.

The plaintext is divided into groups of 64 bytes with the possibility of
the last group being less than 64 bytes. The key is divided into groups
of 128 bytes with the possibility of the last group being less than 128
bytes.

If this yields an equal number of key and plaintext groups, then this is
how the key is used: The SHA512 hash for the first key group is computed
and then used as the seed to generate pseudo-random numbers that determine
the shuffle destination of the bits in the first plaintext group. The
second key group is then combined with the current seed value to produce
a new SHA512 hash. This new hash is used as the seed to generate
pseudo-random numbers that determine the shuffle destination of the bits
in the second plaintext group. This procedure continues to the end of
the groups.

If there are fewer key groups than plaintext groups, then after the last
key group has been incorporated into the seed value that seed is used to
generate pseudo-random numbers for the rest of the groups in the plaintext.
If there are more key groups than plaintext groups, then the size of the
key groups is increased so that the number of key groups will be equal
to the number of plaintext groups.

As mentioned above, the encryption algorithm is implemented using the
Bouncycastle library. This implementation of Crypto-Shuffle is written
in Java. There is a C# implementation of the Bouncycastle library, so
perhaps there will be a C# implementation of Crypto-Shuffle.
