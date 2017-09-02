package com.markgrand.cryptoShuffle.keyShard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.markgrand.cryptoShuffle.AbstractTest;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * <p>Unit tests for JsonUtil.</p>
 * Created by mark.grand on 7/7/2017.
 */
public class JsonUtilTest extends AbstractTest implements JsonSchemaConstants {
    private static JsonSchema jsonSchema;

    private KeyShardSet keyShardSet;

    private static ObjectMapper objectMapper;

    private final Map<PublicKey, PrivateKey> keyDictionary = new HashMap<>();

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
            final Set<KeyPair> keyPairs5 = generateKeyPairs(5);
            final Set<KeyPair> keyPairs3 = generateKeyPairs(3);
            final KeyShardSet.KeyShardingSetBuilder builder = KeyShardSet.newBuilder(AsymmetricEncryptionAlgorithms.RSA);
            final Set<PublicKey> publicKeys5 = keyPairs5.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
            final Set<PublicKey> publicKeys3 = keyPairs3.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
            keyShardSet = builder.addKeyGroup(2,  publicKeys5).addKeyGroup(3,  publicKeys3).build(key4800);
//        addToKeyDictionary(keyPairs3);
//        addToKeyDictionary(keyPairs5);
        } catch (Throwable e) {
            System.err.println("Before");
            e.printStackTrace();
            throw e;
        }
    }

    private void addToKeyDictionary(Set<KeyPair> keyPairs3) {
        for (KeyPair keyPair : keyPairs3) {
            keyDictionary.put(keyPair.getPublic(), keyPair.getPrivate());
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
    public void roundTripTest() throws Exception {
        final ObjectNode jsonObject = (ObjectNode) JsonUtil.keyShardSetToJson(keyShardSet);
        System.out.println("JSON node: " + jsonObject);
        final KeyShardSet reconstructedKeyShardSet = JsonUtil.jsonToKeyShardSet(jsonObject);
        assertEquals(keyShardSet.getShardCount(), reconstructedKeyShardSet.getShardCount());
        assertEquals(keyShardSet.getUuid(), reconstructedKeyShardSet.getUuid());
        assertEquals(keyShardSet.getEncryptionAlgorithm(), reconstructedKeyShardSet.getEncryptionAlgorithm());
        final Collection<KeyShardSet.KeyShardGroup> reconstructedGroups = reconstructedKeyShardSet.getGroups();
        assertEquals(keyShardSet.getGroups().size(), reconstructedGroups.size());
        for (KeyShardSet.KeyShardGroup group: keyShardSet.getGroups()) {
            assertTrue(reconstructedGroups.contains(group));
        }
        assertEquals(keyShardSet.getGroups(), reconstructedKeyShardSet.getGroups());
        assertEquals("original: " + jsonObject + "\n reconstructed: " + JsonUtil.keyShardSetToJson(reconstructedKeyShardSet),
                keyShardSet, reconstructedKeyShardSet);
    }
}
