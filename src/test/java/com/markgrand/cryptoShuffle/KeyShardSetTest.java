package com.markgrand.cryptoShuffle;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * <p>Unit tests for {@link KeyShardSet}</p>
 * Created by Mark Grand on 6/5/2017.
 */
public class KeyShardSetTest {
    private static byte[] key4800;
    private static byte[] key24;
    private KeyPairGenerator keyPairGenerator ;

    @BeforeClass
    public static void initKeys() {
        RandomKeyGenerator generator = new RandomKeyGenerator();
        key4800 = generator.generateKey(4800);
        key24 = generator.generateKey(24);
    }

    @Before
    public void init() throws Exception {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    }

    @Test
    public void makeShardsTest2() {
        final byte[][] shards = KeyShardSet.makeShards(key4800, 2, 2400);
        assertEquals(2, shards.length);
        checkShardContent(shards, key4800);
    }

    @Test
    public void makeShardsTest3() {
        final byte[][] shards = KeyShardSet.makeShards(key24, 3, 8);
        assertEquals(3, shards.length);
        checkShardContent(shards, key24);
    }

    @Test
    public void makeShardsTest5() {
        final byte[][] shards = KeyShardSet.makeShards(key24, 5, 4);
        assertEquals(5, shards.length);
        assertEquals(5, shards[0].length);
        assertEquals(5, shards[1].length);
        assertEquals(5, shards[2].length);
        assertEquals(5, shards[3].length);
        assertEquals(4, shards[4].length);
        checkShardContent(shards, key24);
    }

    @Test
    public void makeShardsTest101() {
        final byte[][] shards = KeyShardSet.makeShards(key4800, 101, 47);
        assertEquals(101, shards.length);
        assertEquals(47, shards[100].length);
        assertEquals(48, shards[0].length);
        assertEquals(48, shards[52].length);
        assertEquals(47, shards[53].length);
        checkShardContent(shards, key4800);
    }

    private void checkShardContent(byte[][] shards, byte[] key) {
        int offset = 0;
        for (int i = 0; i < shards.length; i++) {
            for (int j = 0; j < shards[i].length; j++) {
                if (shards[i][j] != key[offset]) {
                    fail("shards[" + i + "][" + j + "] != key[" + offset + "]");
                }
                offset += 1;
            }
        }
        assertEquals(key.length, offset);
    }

    /**
     * Quick trivial function for encryption. Xor's each bytes of the plain text with the first byte of the public key.
     */
    private BiFunction<PublicKey, byte[], byte[]> trivialEncryption = (publicKey, plaintext) -> {
        byte[] key = publicKey.getEncoded();
        byte[] result = Arrays.copyOf(plaintext, plaintext.length);
        for (int i = 0; i < result.length; i++) {
            result[i] ^= key[0];
        }
        return result;
    };

    @Test
    public void buildTest() {
        final Set<KeyPair> keyPairs5 = generateKeyPairs(5);
        final Set<KeyPair> keyPairs3 = generateKeyPairs(3);
        final KeyShardSet.KeyShardingSetBuilder builder = KeyShardSet.newBuilder(trivialEncryption);
        final Set<PublicKey> publicKeys5 = keyPairs5.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final Set<PublicKey> publicKeys3 = keyPairs3.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final KeyShardSet keyShardSet = builder.addKeyGroup(2,  publicKeys5).addKeyGroup(3,  publicKeys3).build(key4800);
        assertNotNull(keyShardSet.getGuid());
        final Collection<KeyShardSet.KeyShardGroup> groups = keyShardSet.getGroups();
        assertEquals(2, groups.size());
        final Iterator<KeyShardSet.KeyShardGroup> groupIterator = groups.iterator();
        final KeyShardSet.KeyShardGroup thisGroup = groupIterator.next();
        final KeyShardSet.KeyShardGroup group5, group3;
        switch (thisGroup.getKeys().size()) {
            case 5:
                group5 = thisGroup;
                group3 = groupIterator.next();
                break;
            case 3:
                group3 = thisGroup;
                group5 = groupIterator.next();
                break;
            default:
                fail("Group has a size other than 5 or 3!");
                throw new RuntimeException("Group has a size other than 5 or 3!");
        }
        assertEquals(publicKeys5, group5.getKeys());
        assertEquals(publicKeys3, group3.getKeys());
        assertEquals(2, group5.getQuorumSize());
        assertEquals(3, group3.getQuorumSize());
    }

    /**
     * Generate the given quantity of key pairs
     */
    private Set<KeyPair> generateKeyPairs(int quantity) {
        Set<KeyPair> keyPairs = new HashSet<>();
        for (int i = 0; i < quantity; i++) {
            keyPairs.add(keyPairGenerator.generateKeyPair());
        }
        return keyPairs;
    }
}
