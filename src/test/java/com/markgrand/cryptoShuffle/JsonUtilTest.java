package com.markgrand.cryptoShuffle;

import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * <p>Unit tests for JsonUtil.</p>
 * Created by mark.grand on 7/7/2017.
 */
public class JsonUtilTest extends AbstractTest {
    @Test
    public void keyShardSetToJsonTest() {
        final Set<KeyPair> keyPairs5 = generateKeyPairs(5);
        final Set<KeyPair> keyPairs3 = generateKeyPairs(3);
        final KeyShardSet.KeyShardingSetBuilder builder = KeyShardSet.newBuilder(trivialEncryption);
        final Set<PublicKey> publicKeys5 = keyPairs5.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final Set<PublicKey> publicKeys3 = keyPairs3.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final KeyShardSet keyShardSet = builder.addKeyGroup(2,  publicKeys5).addKeyGroup(3,  publicKeys3).build(key4800);

    }
}
