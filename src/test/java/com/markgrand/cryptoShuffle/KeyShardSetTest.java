package com.markgrand.cryptoShuffle;

import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * <p>Unit tests for {@link KeyShardSet}</p>
 * Created by Mark Grand on 6/5/2017.
 */
public class KeyShardSetTest {
    private static byte[] key4800 ;
    private static byte[] key24;

    @BeforeClass
    public static void initKeys() {
        RandomKeyGenerator generator = new RandomKeyGenerator();
        key4800 = generator.generateKey(4800);
        key24 = generator.generateKey(24);
    }

    @Test
    public void makeShardsTest2() {
        final byte[][] shards = KeyShardSet.makeShards(key4800,2, 2400);
        assertEquals(2, shards.length);
        checkShardContent(shards, key4800);
    }

    @Test
    public void makeShardsTest3() {
        final byte[][] shards = KeyShardSet.makeShards(key24,3, 8);
        assertEquals(3, shards.length);
        checkShardContent(shards, key24);
    }

    @Test
    public void makeShardsTest5() {
        final byte[][] shards = KeyShardSet.makeShards(key24,5, 4);
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
        final byte[][] shards = KeyShardSet.makeShards(key4800,101, 47);
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
}
