package com.markgrand.cryptoShuffle.keyManagement;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.markgrand.cryptoShuffle.AbstractTest;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * <p>Unit tests for JsonUtil.</p>
 * Created by mark.grand on 7/7/2017.
 */
public class JsonUtilTest extends AbstractTest implements JsonSchemaConstants {
    private static JsonSchema jsonSchema;

    private KeyShardSet keyShardSet;
    private Set<KeyPair> keyPairs5;
    private Set<KeyPair> keyPairs3;

    private static ObjectMapper objectMapper;

    @BeforeClass
    public static void initSchema() throws Exception {
        try {
            final File file = new File(JSON_SCHEMA_FILE_PATH);
            System.out.println("Validating syntax of " + file.getAbsolutePath());
            objectMapper = new ObjectMapper();
            final JsonNode jsonNode = objectMapper.readTree(file);
            jsonSchema = JsonSchemaFactory.byDefault().getJsonSchema(jsonNode);
        } catch (Throwable e) {
            System.err.println("BeforeClass");
            e.printStackTrace();
            throw e;
        }
    }

    @Before
    public void createKeyShardSet() {
        try {
            keyPairs5 = generateKeyPairs(5);
            keyPairs3 = generateKeyPairs(3);
            final KeyShardSet.KeyShardingSetBuilder builder = KeyShardSet.newBuilder(AsymmetricEncryptionAlgorithm.RSA);
            final Set<PublicKey> publicKeys5 = keyPairs5.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
            final Set<PublicKey> publicKeys3 = keyPairs3.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
            keyShardSet = builder.addKeyGroup(2,  publicKeys5).addKeyGroup(3,  publicKeys3).build(key4800);
        } catch (Throwable e) {
            System.err.println("Before");
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    public void keyShardSetToJsonTest() throws Exception {
        final JsonNode jsonNode = JsonUtil.keyShardSetToJson(keyShardSet);
        System.out.println(jsonSchema.validate(jsonNode, true).toString());
        assertTrue(jsonNode.toString(),jsonSchema.validInstance(jsonNode));
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void missingVersionTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        jsonObject.remove(JsonUtil.VERSION_NAME);
        JsonUtil.jsonToKeyShardSet(jsonObject);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void unsupportedVersionTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        jsonObject.remove(JsonUtil.VERSION_NAME);
        jsonObject.put(JsonUtil.VERSION_NAME, "0");
        JsonUtil.jsonToKeyShardSet(jsonObject);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void nullVersionTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        jsonObject.remove(JsonUtil.VERSION_NAME);
        jsonObject.replace(JsonUtil.VERSION_NAME, objectMapper.getNodeFactory().nullNode());
        JsonUtil.jsonToKeyShardSet(jsonObject);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void missingAssymentricEncryptionAlgorithmTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        jsonObject.remove(JsonUtil.ENCRYPTION_ALGORITHM_NAME);
        JsonUtil.jsonToKeyShardSet(jsonObject);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void missingShardCountTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        jsonObject.remove(JsonUtil.SHARD_COUNT_NAME);
        JsonUtil.jsonToKeyShardSet(jsonObject);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void wrongTypeShardCountTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        jsonObject.replace(JsonUtil.SHARD_COUNT_NAME, objectMapper.getNodeFactory().nullNode());
        JsonUtil.jsonToKeyShardSet(jsonObject);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void zeroShardCountTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        jsonObject.replace(JsonUtil.SHARD_COUNT_NAME, objectMapper.getNodeFactory().numberNode(0));
        JsonUtil.jsonToKeyShardSet(jsonObject);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void noGroupsTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        jsonObject.replace(JsonUtil.GROUPS_NAME, objectMapper.getNodeFactory().arrayNode());
        JsonUtil.jsonToKeyShardSet(jsonObject);
    }

    @Test
    public void publicKeyTest() {
        final KeyPair keyPair = generateKeyPair();
        final PublicKey publicKey = keyPair.getPublic();
        final byte[] encodedPublicKey = publicKey.getEncoded();
        final PublicKey reconstruction = JsonUtil.bytesToPublicKey(encodedPublicKey);
        assertEquals(publicKey, reconstruction);
        assertEquals(publicKey.hashCode(), reconstruction.hashCode());
    }

    @Ignore
    @Test
    public void roundTripTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        System.out.println("JSON node: " + jsonObject);
        final KeyShardSet reconstructedKeyShardSet = JsonUtil.jsonToKeyShardSet(jsonObject);
        assertEquals(keyShardSet.getShardCount(), reconstructedKeyShardSet.getShardCount());
        assertEquals(keyShardSet.getUuid(), reconstructedKeyShardSet.getUuid());
        assertEquals(keyShardSet.getEncryptionAlgorithm(), reconstructedKeyShardSet.getEncryptionAlgorithm());
//        final Collection<KeyShardSet.KeyShardGroup> reconstructedGroups = reconstructedKeyShardSet.getGroups();
        final Iterator<KeyPair> iterator5 = keyPairs5.iterator();
        keyShardSet.decryptShardsForPublicKey(iterator5.next());
        keyShardSet.decryptShardsForPublicKey(iterator5.next());
        final Iterator<KeyPair> iterator3 = keyPairs3.iterator();
        keyShardSet.decryptShardsForPublicKey(iterator3.next());
        keyShardSet.decryptShardsForPublicKey(iterator3.next());
        keyShardSet.decryptShardsForPublicKey(iterator3.next());
        final Optional<byte[]> decrypted = keyShardSet.getDecryptedKey();
        assertTrue(decrypted.isPresent());
        assertArrayEquals(key4800, decrypted.get());
    }

    @Test
    public void multiEncryptionSerializationTest() {
        Set<KeyPair> keyPairs = generateKeyPairs(3);
        final MultiEncryption multiEncryption
                = new MultiEncryption(key24, keyPairs.stream().map(KeyPair::getPublic).collect(Collectors.toList()));
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.multiEncryptionToJson(multiEncryption);
        jsonObject.get(JsonUtil.ENCRYPTION_ALGORITHM_NAME).asText();
        assertEquals(JsonUtil.VERSION1_0, jsonObject.get(JsonUtil.VERSION_NAME).asText());
        assertEquals("RSA", jsonObject.get(JsonUtil.ENCRYPTION_ALGORITHM_NAME).asText());
        final ObjectNode keysObject = (ObjectNode) jsonObject.get(JsonUtil.ENCRYPTIONS_NAME);
        assertEquals(3, keysObject.size());
    }

    @Test
    public void multiEncryptionRoundTripTest() throws Exception {
        Set<KeyPair> keyPairs = generateKeyPairs(3);
        final MultiEncryption multiEncryption
                = new MultiEncryption(key24, keyPairs.stream().map(KeyPair::getPublic).collect(Collectors.toList()));
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.multiEncryptionToJson(multiEncryption);
        final MultiEncryption reconstructedMultiEncryption = JsonUtil.jsonToMultiEncryption(jsonObject);
        final Optional<byte[]> reconstructedKey24 = reconstructedMultiEncryption.decrypt(keyPairs.iterator().next());
        assertTrue(reconstructedKey24.isPresent());
        assertArrayEquals(key24, reconstructedKey24.get());
    }
}
