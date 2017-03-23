# crypto-shuffle

The symmetric encryption algorithm used for applications like protecting
the secrecy of blockchain contents needs to be very strong. The
symmetric encryption algorithm should have these properties:


* Longer encrypted texts should require more effort to crack than shorter texts.
* It should be necessary to decrypt the entire text at once, rather than
  being possible to decrypt in pieces as with a block cypher.
* There should be no upper limit on the key length.
* One of the challenges of cracking the encryption should be that there
  will be multiple possible solutions that look reasonable and no clue
  as to which is correct.

The algorithm implemented in this package is based on doing a random
shuffle of the ones and zeros in a plaintext. The actual order of the
shuffle is based on the encryption key.

Here is a high-level description of the encryption algorithm:

1. Inputs to the algorithm are a plaintext message that is a sequence of
   bytes and a key that is an arbitrary sequence of bytes.
2. Compute a SHA3-512 hash of the key.
3. Use the hash as the seed for a pseudo-random sequence of numbers. The
   following steps will be based on this sequence. The decryption
   operation will consist of performing the following steps in reverse
   using the same sequence of pseudo-random numbers.

   For interoperability, all implementations of this encryption
   algorithm will need to use the same pseudo-random number generator.
   The DigestRandomGenerator class from the Bouncycastle library is used
   for this purpose. There is a paper that includes an analysis of this
   pseudo-random number generator at
   https://www.hgi.rub.de/media/nds/veroeffentlichungen/2013/03/25/paper_2.pdf.
4. Append to the plaintext bytes containing the length of the plaintext
   as an unsigned binary integer. For consistency, the bytes should be
   appended in big-endian order (most significant byte first, least
   significant byte last). The length of the integer should be the
   minimum number of bytes needed to represent the value.

   The reason for not using a fixed number of bytes to represent the
   length is to avoid having a high-order byte that is likely to be zero
   and thereby provide a clue as to location of the length value.
5. Append a byte to the plaintext that contains the number of bytes
   appended to the plaintext in the previous step.  The actual value
   stored in this byte should be the sum of the number of bytes plus a
   random value, ignoring overflow. The reason for adding the random
   number is to avoid having a predictable value in this position.
6. This step has two purposes. Firstly we want to avoid giving any clue
   about the plaintext from the relative number of ones and zeros in the
   encrypted message. Secondly, we want to add extraneous bits to ensure
   that a brute force attempt to decrypt the encrypted text will result
   in multiple candidates for the plaintext that will be wrong but
   appear to be a reasonable solution.

   Compute a random number r that is between _n_ and _2n_, where _n_ is
   the current length of the plaintext. Using a separate random number
   generator that is independent of the one we are using for every other
   step, append _r_ random bytes to the plaintext. If the total number
   of ones and zeros in the plaintext is not equal, then using the same
   independent pseudo random number generator, invert randomly selected
   bits in the appended bytes until the number of ones and zeros in the
   plaintext is equal.
7. Perform a shuffle of the plaintext based on pseudo-random numbers.