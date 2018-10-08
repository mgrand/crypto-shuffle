package com.markgrand.cryptoShuffle.keyManagement;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * This interface associates cryptoshuffle keys with a {@link UUID}. It is intended as way of managing a one time key
 * pad for encrypting content in blockchain transactions using keys that you will be sharing with the same set of
 * parties.
 * <p>
 * The intended use case is that each key is used to encrypt content in one blockchain transaction. The interface
 * associates each cryptoshuffle key with a UUID.
 * <p>
 * When you know that you will be wanting to be creating blockchain transactions that will contain some data you want to
 * encrypt and that you will be wanting to share the encryption keys for these transactions with the same parties, you
 * begin by creating a {@code OneTimeKeyPad} object that will correspond to that exact set of parties.
 * <p>
 * The next step is to generate and add some encryption keys to the pad. You do this by calling the {@link
 * #generateKeys(int, int)} method. This generates and adds a batch of keys to the pad. It also returns the generated
 * keys in a {@link Map} that you can share with the parties that you want to know the encryption keys.
 * <p>
 * When the other parties receive the {@link Map}, they can pass it to the {@link #addSharedKeys(Map)} method to add the
 * encryption keys to this pad as used encryptionkeys.
 * <p>
 * When you encrypt content in a blockchain transaction, you also include its UUID as plaintext in the blockchain
 * transaction. You and others have the pad that still contains all of the used encryption keys, so you can look up the
 * key to decrypt by its UUID.
 *
 * @author Mark Grand
 */
@SuppressWarnings("WeakerAccess")
public interface OneTimeKeyPad {
    /**
     * Generate and add the given number of new encryption keys to this pad as unused keys.
     *
     * @param count     The number of new encryption keys to generate. Must be greater than zero.
     * @param keyLength The length in bytes of the encryption keys to be generated. Values less then 8 will be treated
     *                  as 8.
     * @return a {@link Map} object whose keys are the UUID of the generated encryption keyse and whose values are the
     * encryption keys. This returned {@link Map} can be used to share the newly generated keys and their IDs.
     */
    Map<UUID, byte[]> generateKeys(int count, int keyLength);

    /**
     * Generate and add the given number of new encryption keys to this pad as unused keys.
     *
     * @param count        The number of new encryption keys to generate. Must be greater than zero.
     * @param minKeyLength The minimum length in bytes of the encryption keys to be generated. Values less then 8 will
     *                     be treated as 8.
     * @param maxKeyLength The maximum length in bytes of the encryption keys to be generated.
     * @return a {@link Map} object whose keys are the UUID of the generated encryption keyse and whose values are the
     * encryption keys. This returned {@link Map} can be used to share the newly generated keys and their IDs.
     */
    Map<UUID, byte[]> generateKeys(int count, int minKeyLength, int maxKeyLength);

    /**
     * Add the encryption keys in the given map to this pad as used keys.
     *
     * @param sharedKeyMap The map whose contents are to be added to this pad.
     */
    void addSharedKeys(Map<UUID, byte[]> sharedKeyMap);

    /**
     * Return the next unused encryption key in this pad and its UUID.
     *
     * @return an {@link Optional} object that contains a {@link java.util.Map.Entry} whose value is the encryption key
     * and whose key is the encryption key's UUID, if there are any unused keys in the pad. If there are no unused keys,
     * returns an empty {@code Optional} object.
     */
    Optional<Map.Entry<UUID, byte[]>> getUnusedKey();

    /**
     * This method sets a strategy that makes using the {@link #getUnusedKey()} more convenient by ensuring that
     * getUnusedKey always has an unused key to return.
     * <p>
     * When there are no unused keys in this pad and {@link #getUnusedKey()} is called, it returns an empty result. If
     * there is any possibility that {@link #getUnusedKey()} will return an empty result, then every call to
     * getUnusedKey must be followed by an if statement that checks for the empty result. If the result is empty it
     * calls {@link #generateKeys(int, int)} and then calls {@link #getUnusedKey()} again.
     * <p>
     * Using this method is a way to avoid having to follow every call to getUnusedKey with an if statement. After this
     * method is called, if {@code getUnusedKey} is called there are no unused keys in the pad then the {@code count}
     * and {@code keyLength} values that were passed to this method are passed to the {@link #generateKeys(int, int)}
     * method which generates and new keys to the pad. The {@link Map} that the {@code generateKeys} method returns is
     * passed to the {@code transmitter} method that is a parameter of this method. It is expected that the {@code
     * transmitter} method will asynchronously transmit {@code Map } containing the newly generated keys to the parties
     * that the keys are to be shared with.
     *
     * @param count       The number of new keys to be generated at one time.
     * @param keyLength   The length of the keys to be generated in bytes.
     * @param transmitter The method to be called to transmit the newly generated keys.
     * @see #clearAutoGenerateKeys()
     */
    void autoGenerateKeys(int count, int keyLength, Consumer<Map<UUID, byte[]>> transmitter);

    /**
     * This method sets a strategy that makes using the {@link #getUnusedKey()} more convenient by ensuring that
     * getUnusedKey always has an unused key to return.
     * <p>
     * When there are no unused keys in this pad and {@link #getUnusedKey()} is called, it returns an empty result. If
     * there is any possibility that {@link #getUnusedKey()} will return an empty result, then every call to
     * getUnusedKey must be followed by an if statement that checks for the empty result. If the result is empty it
     * calls {@link #generateKeys(int, int)} and then calls {@link #getUnusedKey()} again.
     * <p>
     * Using this method is a way to avoid having to follow every call to getUnusedKey with an if statement. After this
     * method is called, if {@code getUnusedKey} is called there are no unused keys in the pad then the {@code count},
     * {@code minKeyLength} and {@code maxKeyLength} values that were passed to this method are passed to the {@link
     * #generateKeys(int, int, int)} method which generates and new keys to the pad. The {@link Map} that the {@code
     * generateKeys} method returns is passed to the {@code transmitter} method that is a parameter of this method. It
     * is expected that the {@code transmitter} method will asynchronously transmit {@code Map } containing the newly
     * generated keys to the parties that the keys are to be shared with.
     *
     * @param count        The number of new keys to be generated at one time.
     * @param minKeyLength The length of the keys to be generated in bytes.
     * @param maxKeyLength The length of the keys to be generated in bytes.
     * @param transmitter  The method to be called to transmit the newly generated keys.
     * @see #clearAutoGenerateKeys()
     */
    void autoGenerateKeys(int count, int minKeyLength, int maxKeyLength, Consumer<Map<UUID, byte[]>> transmitter);

    /**
     * This undoes the effect of previous calls to {@link #autoGenerateKeys}. After this method is called, {@link
     * #getUnusedKey()} will return an empty result if it is called when there are no unused keys in the pad.
     */
    void clearAutoGenerateKeys();

    /**
     * Get the used encryption key that is associated in the pad with the given {@link UUID}.
     *
     * @param uuid the UUID to look for.
     * @return an {@link Optional} object that contains the key or an empty {@code Optional} object if there is no key
     * in the pad that is associated with the given {@code UUID}
     */
    Optional<byte[]> lookupKey(UUID uuid);

    /**
     * Get the number of unused keys in this pad.
     *
     * @return the number of unused keys in this pad.
     */
    int getUnusedKeyCount();

    /**
     * Get the number of used keys in this pad.
     *
     * @return the number of used keys in this pad.
     */
    int getUsedKeyCount();
}
