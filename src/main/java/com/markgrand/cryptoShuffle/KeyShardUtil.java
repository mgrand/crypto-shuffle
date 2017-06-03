package com.markgrand.cryptoShuffle;

/**
 * <p>
 * Utility for breaking keys into multiple shards so that they can be securely shared by multiple people.</p>
 * <p>
 * A key shard set consists of a long cryptoshuffle key that has been broken into two or more pieces called shards and
 * some public keys. One or more of the key shards is associated with each of the public keys. The key shards that are
 * associated with a public key are encrypted using that public key. If a key shard is associated with more than one
 * public key, different copy of the shard will be associated with each public can and encrypted with that public key.
 * </p>
 * <p>
 * Key shards have two distinct uses.
 * </p>
 * <p>Created by Mark Grand on 6/1/2017.</p>
 */
public class KeyShardUtil {
}
