package com.markgrand.cryptoShuffle.keyShard;

import static org.junit.Assert.*;
import org.junit.Test;

import javax.crypto.SecretKey;

public class SymmetricEncryptionAlgorithmTest {
    @Test
    public void aesRoundTripTest() {
        //noinspection SpellCheckingInspection
        final byte[] plainText = ("aosdif pairf p9qfr p9ashfpoajshdf palshdf gsuhgf pioauhgf pouh2498yep98ghupe977iuh3grefdv9iuhekrgfduihkjfudsoihjkroifuhdkj"
                + "98uohjlegrfd8ouhljqgerf[oipuhergfkdsjlipiuervbteoijffgpeitrbsejiophgsrjk[georprtohe[irljjjn4398yuhtei").getBytes();
        SecretKey secretKey = SymmetricEncryptionAlgorithm.AES.generateKey();
        final byte[] encryptedText = SymmetricEncryptionAlgorithm.AES.encrypt(secretKey, plainText);
        final byte[] decryptedText = SymmetricEncryptionAlgorithm.AES.decrypt(secretKey.getEncoded(), encryptedText);
        assertArrayEquals(plainText, decryptedText);
    }
}
