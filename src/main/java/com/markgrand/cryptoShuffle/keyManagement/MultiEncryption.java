package com.markgrand.cryptoShuffle.keyManagement;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * The crypto-shuffle package includes a convenient mechanism for creating a single JSON object that contains the
 * encrypted versions of a plaintext that correspond to multiple public keys. This is the MultiEncryption class.
 * <p>
 * To create a MultiEncryption object, you pass the constructor a plain text and a collection of one or more public
 * keys. The constructed object contains versions of the plain text encrypted by each of the public keys.
 * <p>
 * To decrypt the contents of a MultiEncryption object, pass a public key and its corresponding private key to the
 * MultiEncryption object's decrypt method. If the MultiEncryption object contains an encrypted text that was
 * encrypted with the given public key, it uses the corresponding private key to decrypt the text.
 *
 * @author Mark Grand
 */
public class MultiEncryption {
    private final Map<PublicKey, byte[]> encryptions = new HashMap<>();


}
