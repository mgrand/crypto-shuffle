package com.markgrand.cryptoShuffle.keyManagement;

import com.markgrand.cryptoShuffle.RandomKeyGenerator;
import org.junit.Before;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.*;

public class InMemoryOneTimeKeyPadTest {
    private OneTimeKeyPad pad;

    @Before
    public void setUp() throws Exception {
        pad = new InMemoryOneTimeKeyPad();
    }

    @Test
    public void getUnusedKeyCount() throws Exception {
        assertEquals(0, pad.getUnusedKeyCount());
        pad.generateKeys(50, 80);
        assertEquals(50, pad.getUnusedKeyCount());
        pad.generateKeys(70, 80);
        pad.generateKeys(120, 80);
    }

    @Test
    public void lookupKey() throws Exception {
        assertEquals(Optional.empty(), pad.lookupKey(UUID.randomUUID()));
        UUID uuid = UUID.randomUUID();
        byte[] key = RandomKeyGenerator.getThreadLocalInstance().generateKey(88);
        Map<UUID, byte[]> map = new HashMap<>();
        map.put(uuid, key);
        pad.addSharedKeys(map);
        //noinspection ConstantConditions
        assertArrayEquals(key, pad.lookupKey(uuid).get());
        assertEquals(Optional.empty(), pad.lookupKey(UUID.randomUUID()));
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    public void addSharedKeys() throws Exception {
        assertEquals(0, pad.getUsedKeyCount());
        Map<UUID, byte[]> map = new HashMap<>();
        RandomKeyGenerator generator = RandomKeyGenerator.getThreadLocalInstance();
        UUID uuid1 = UUID.randomUUID();
        UUID uuid2 = UUID.randomUUID();
        UUID uuid3 = UUID.randomUUID();
        byte[] key1 = generator.generateKey(88);
        byte[] key2 = generator.generateKey(98);
        byte[] key3 = generator.generateKey(32);
        map.put(uuid1, key1);
        map.put(uuid2, key2);
        map.put(uuid3, key3);
        pad.addSharedKeys(map);
        assertEquals(3, pad.getUsedKeyCount());
        assertArrayEquals(key1, pad.lookupKey(uuid1).get());
        assertArrayEquals(key2, pad.lookupKey(uuid2).get());
        assertArrayEquals(key3, pad.lookupKey(uuid3).get());
    }

    @Test(expected = IllegalArgumentException.class)
    public void generateNegativeKeys() throws Exception {
        pad.generateKeys(-1, 99);
    }

    @Test(expected = IllegalArgumentException.class)
    public void generateZeroKeys() throws Exception {
        pad.generateKeys(0, 99);
    }

    @Test
    public void generateKeys() throws Exception {
        assertEquals(0, pad.getUsedKeyCount());
        Map<UUID, byte[]> map = pad.generateKeys(5, 99);
        assertEquals(5, pad.getUnusedKeyCount());
        assertEquals(5, map.size());
        Set<Map.Entry<UUID, byte[]>> mapEntries = map.entrySet();
        for (int i = 5; i > 0; i--) {
            assertEquals(i, map.size());
            Optional<Map.Entry<UUID, byte[]>> result = pad.getUnusedKey();
            assertTrue(result.isPresent());
            assertEquals(99, result.get().getValue().length);
            assertTrue(mapEntries.contains(result.get()));
            assertTrue(mapEntries.remove(result.get()));
            assertEquals(i - 1, map.size());
        }
    }

    @Test
    public void generateKeys1() throws Exception {
        assertEquals(0, pad.getUsedKeyCount());
        final int count = 50;
        final Map<UUID, byte[]> map = pad.generateKeys(count, 95, 104);
        assertEquals(count, pad.getUnusedKeyCount());
        assertEquals(count, map.size());
        Set<Map.Entry<UUID, byte[]>> mapEntries = map.entrySet();
        for (int i = count; i > 0; i--) {
            assertEquals(i, map.size());
            Optional<Map.Entry<UUID, byte[]>> result = pad.getUnusedKey();
            assertTrue(result.isPresent());
            assertTrue(95 <= result.get().getValue().length);
            assertTrue(104 >= result.get().getValue().length);
            assertTrue(mapEntries.contains(result.get()));
            assertTrue(mapEntries.remove(result.get()));
            assertEquals(i - 1, map.size());
        }
    }

    @Test
    public void getNextUnusedKeyFixed() throws Exception {
        assertEquals(0, pad.getUsedKeyCount());
        assertFalse(pad.getUnusedKey().isPresent());
        final boolean[] wasCalled = new boolean[1];
        pad.autoGenerateKeys(2, 88, uuidMap -> {
            assertEquals(2, uuidMap.size());
            wasCalled[0] = true;
        });
        assertTrue(pad.getUnusedKey().isPresent());
        pad.autoGenerateKeys(2, 88, uuidMap -> fail("auto-generate logic should not be called here."));
        assertTrue(pad.getUnusedKey().isPresent());
        assertTrue(wasCalled[0]);
        pad.clearAutoGenerateKeys();
        assertFalse(pad.getUnusedKey().isPresent());
    }

    @Test
    public void getNextUnusedKeyVariable() throws Exception {
        assertEquals(0, pad.getUsedKeyCount());
        assertFalse(pad.getUnusedKey().isPresent());
        final boolean[] wasCalled = new boolean[1];
        pad.autoGenerateKeys(2, 88, 111, uuidMap -> {
            assertEquals(2, uuidMap.size());
            wasCalled[0] = true;
        });
        assertTrue(pad.getUnusedKey().isPresent());
        pad.autoGenerateKeys(2, 88, 111, uuidMap -> fail("auto-generate logic should not be called here."));
        assertTrue(pad.getUnusedKey().isPresent());
        assertTrue(wasCalled[0]);
        pad.clearAutoGenerateKeys();
        assertFalse(pad.getUnusedKey().isPresent());
    }

    @Test(expected = IllegalArgumentException.class)
    public void autoGenerateKeys() throws Exception {
        pad.autoGenerateKeys(0, 99, uuidMap -> {});
    }

    @Test(expected = IllegalArgumentException.class)
    public void autoGenerateKeys1() throws Exception {
        pad.autoGenerateKeys(0, 99, 109, uuidMap -> {});
    }
}