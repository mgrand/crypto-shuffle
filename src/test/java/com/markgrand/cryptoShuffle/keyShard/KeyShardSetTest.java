package com.markgrand.cryptoShuffle.keyShard;

import com.markgrand.cryptoShuffle.AbstractTest;
import com.markgrand.cryptoShuffle.keyManagement.AsymmetricEncryptionAlgorithms;
import org.junit.Ignore;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * <p>Unit tests for {@link KeyShardSet}</p>
 * Created by Mark Grand on 6/5/2017.
 */
public class KeyShardSetTest extends AbstractTest {
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

    @Test
    public void buildTest() {
        final Set<KeyPair> keyPairs5 = generateKeyPairs(5);
        final Set<KeyPair> keyPairs3 = generateKeyPairs(3);
        final KeyShardSet.KeyShardingSetBuilder builder = KeyShardSet.newBuilder(AsymmetricEncryptionAlgorithms.RSA);
        final Set<PublicKey> publicKeys5 = keyPairs5.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final Set<PublicKey> publicKeys3 = keyPairs3.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final KeyShardSet keyShardSet = builder.addKeyGroup(2,  publicKeys5)
                .addKeyGroup(3,  publicKeys3)
                .build(key4800);
        assertNotNull(keyShardSet.getUuid());
        assertEquals(8, keyShardSet.getShardCount());
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
        checkGroupShardsPerKey(group5, 4);
        checkGroupShardsPerKey(group3, 1);
        checkGroupCoverage(keyShardSet);
    }

    private void checkGroupCoverage(KeyShardSet keyShardSet) {
        final int shardCount = keyShardSet.getShardCount();
        final int[] coverageFlags = new int[shardCount];
        int groupNumber = 0;
        for (final KeyShardSet.KeyShardGroup group: keyShardSet.getGroups()) {
            int keyNumber = 0;
            for (final PublicKey key: group.getKeys()) {
                System.out.print("Group " + groupNumber + " key " + keyNumber + ": ");
                for (final Map.Entry<Integer, EncryptedShard> shard: group.getEncryptedShardsForKey(key).entrySet()) {
                    coverageFlags[shard.getKey()] = 1;
                    System.out.print(shard.getKey() + " ");
                }
                System.out.println();
                keyNumber += 1;
            }
            groupNumber += 1;
        }
        for (int i = 0; i< shardCount; i++) {
            if (coverageFlags[i] == 0) {
                fail("Not all shards covered. " + Arrays.toString(coverageFlags));
            }
        }
    }

    private void checkGroupShardsPerKey(KeyShardSet.KeyShardGroup group, int expectedSize) {
        group.getKeys().forEach(key -> assertEquals(expectedSize, group.getEncryptedShardsForKey(key).size()));
    }

    @Ignore
    @Test
    public void roundTripTest4800() {
        final Set<KeyPair> keyPairs5 = generateKeyPairs(5);
        final Set<KeyPair> keyPairs3 = generateKeyPairs(3);
        final KeyShardSet.KeyShardingSetBuilder builder = KeyShardSet.newBuilder(AsymmetricEncryptionAlgorithms.RSA);
        final Set<PublicKey> publicKeys5 = keyPairs5.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final Set<PublicKey> publicKeys3 = keyPairs3.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final KeyShardSet keyShardSet = builder.addKeyGroup(2,  publicKeys5)
                                                .addKeyGroup(3,  publicKeys3)
                                                .build(key4800);
        assertFalse(keyShardSet.getDecryptedKey().isPresent());
        decryptKeyPairs(keyShardSet, keyPairs5);
        assertFalse(keyShardSet.getDecryptedKey().isPresent());
        decryptKeyPairs(keyShardSet, keyPairs3);
        assertTrue(keyShardSet.getDecryptedKey().isPresent());

        assertArrayEquals(key4800, keyShardSet.getDecryptedKey().get());
    }

    private void decryptKeyPairs(KeyShardSet keyShardSet, Set<KeyPair> keyPairs) {
        for (KeyPair keyPair : keyPairs) {
            keyShardSet.decryptShardsForPublicKey(keyPair.getPublic(), keyPair.getPrivate());
        }
    }

}
