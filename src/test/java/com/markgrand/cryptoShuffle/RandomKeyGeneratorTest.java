package com.markgrand.cryptoShuffle;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit test class for {@link RandomKeyGenerator}
 * Created by Mark Grand on 5/29/2017.
 */
@SuppressWarnings("unused")
public class RandomKeyGeneratorTest {
    @Test
    public void generateFixedLength() {
        final RandomKeyGenerator generator = new RandomKeyGenerator();
        final byte[] key23 = generator.generateKey(23);
        assertEquals(23, key23.length);
        final byte[] key8 = generator.generateKey(5);
        assertEquals(8, key8.length);
    }

    @Test
    public void generateVariableLength() {
        final RandomKeyGenerator generator = new RandomKeyGenerator();
        final byte[] keyLong = generator.generateKey(50,60);
        assertTrue(keyLong.length >= 50);
        assertTrue(keyLong.length <= 60);
        final byte[] key20 = generator.generateKey(20,6);
        assertEquals(20, key20.length);
    }

    @Test
    public void getThreadLocal() throws Exception {
        final RandomKeyGenerator generator = RandomKeyGenerator.getThreadLocalInstance();
        assertSame(generator, RandomKeyGenerator.getThreadLocalInstance());
        RandomKeyGenerator[] generatorHolder = new RandomKeyGenerator[1];
        Thread t = new Thread(() -> generatorHolder[0] = RandomKeyGenerator.getThreadLocalInstance());
        t.start();
        t.join();
        assertNotSame(generator, generatorHolder[0]);
    }
}
