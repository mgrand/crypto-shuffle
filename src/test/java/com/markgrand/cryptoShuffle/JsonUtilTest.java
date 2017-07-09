package com.markgrand.cryptoShuffle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * <p>Unit tests for JsonUtil.</p>
 * Created by mark.grand on 7/7/2017.
 */
public class JsonUtilTest extends AbstractTest implements JsonSchemaConstants {
    private static JsonSchema jsonSchema;

    @BeforeClass
    public static void initSchema() throws Exception {
        File file = new File(JSON_SCHEMA_FILE_PATH);
        System.out.println("Validating syntax of " + file.getAbsolutePath());
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(file);
        jsonSchema = JsonSchemaFactory.byDefault().getJsonSchema(jsonNode);
    }

    @Test
    public void keyShardSetToJsonTest() throws Exception {
        final Set<KeyPair> keyPairs5 = generateKeyPairs(5);
        final Set<KeyPair> keyPairs3 = generateKeyPairs(3);
        final KeyShardSet.KeyShardingSetBuilder builder = KeyShardSet.newBuilder(trivialEncryption);
        final Set<PublicKey> publicKeys5 = keyPairs5.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final Set<PublicKey> publicKeys3 = keyPairs3.stream().map(KeyPair::getPublic).collect(Collectors.toSet());
        final KeyShardSet keyShardSet = builder.addKeyGroup(2,  publicKeys5).addKeyGroup(3,  publicKeys3).build(key4800);

        final JsonNode jsonNode = JsonUtil.keyShardSetToJson(keyShardSet);
        System.out.println(jsonSchema.validate(jsonNode, true).toString());
        Assert.assertTrue(jsonNode.toString(),jsonSchema.validInstance(jsonNode));
    }
}
