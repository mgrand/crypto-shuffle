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
6. The purpose of this step is to add random extraneous bits to ensure
   that a brute force attempt to decrypt the encrypted text will result
   in multiple candidates for the plaintext that will be wrong but
   appear to be a reasonable solution.

   Using a separate random number that is in no way dependent on the key
   we are using, append random bytes to the plaintext to double the
   length of the plaintext.
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
7. Perform a shuffle of the plaintext based on pseudo-random numbers.