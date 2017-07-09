package com.markgrand.cryptoShuffle;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * <p>Utility class for converting instances of classes in this package to and from JSON.</p>
 * Created by mark.grand on 7/5/2017.
 */
@SuppressWarnings("WeakerAccess")
public class JsonUtil {
    private final static ObjectMapper objectMapper = new ObjectMapper();

    static {
        final SimpleModule module = new SimpleModule("KeyShardSet");
        module.addSerializer(KeyShardSet.class, new KeyShardSetSerializer());
        module.addSerializer(KeyShardSet.KeyShardGroup.class, new KeyShardGroupSerializer());
        objectMapper.registerModule(module);
    }

    public static JsonNode keyShardSetToJson(final KeyShardSet keyShardSet) {

        return objectMapper.valueToTree(keyShardSet);
    }

    private static class KeyShardSetSerializer extends StdSerializer<KeyShardSet> {
        public KeyShardSetSerializer() {
            this(null);
        }

        public KeyShardSetSerializer(Class<KeyShardSet> t) {
            super(t);
        }

        @Override
        public void serialize(KeyShardSet value, JsonGenerator jsonGenerator, SerializerProvider provider) throws IOException {
            jsonGenerator.writeStartObject();
            jsonGenerator.writeStringField("version", "1.0");
            jsonGenerator.writeStringField("encryptionAlgorithm", "RSA");
            jsonGenerator.writeStringField("uuid", value.getGuid().toString());
            jsonGenerator.writeNumberField("shardCount", value.getShardCount());
            jsonGenerator.writeArrayFieldStart("groups");
            for (KeyShardSet.KeyShardGroup group : value.getGroups()) {
                jsonGenerator.writeObject(group);
            }
            jsonGenerator.writeEndArray();
            jsonGenerator.writeEndObject();
        }
    }

    private static class KeyShardGroupSerializer extends StdSerializer<KeyShardSet.KeyShardGroup> {
        public KeyShardGroupSerializer() {
            this(null);
        }

        public KeyShardGroupSerializer(Class<KeyShardSet.KeyShardGroup> t) {
            super(t);
        }


        @Override
        public void serialize(KeyShardSet.KeyShardGroup value,
                              JsonGenerator jsonGenerator, SerializerProvider provider) throws IOException {
            jsonGenerator.writeStartObject();
            jsonGenerator.writeNumberField("quorumSize", value.getQuorumSize());
            jsonGenerator.writeArrayFieldStart("keyMap");
            serializeGroupPublicKeys(value, jsonGenerator);
            jsonGenerator.writeEndArray();
            jsonGenerator.writeEndObject();
        }

        private void serializeGroupPublicKeys(KeyShardSet.KeyShardGroup value, JsonGenerator jsonGenerator) throws IOException {
            for (PublicKey publicKey : value.getKeys()) {
                jsonGenerator.writeStartObject();
                final String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                jsonGenerator.writeStringField("publicKey", encodedPublicKey);
                jsonGenerator.writeArrayFieldStart("shards");
                final Map<Integer, byte[]> shards = value.getShardsForKey(publicKey);
                for (Map.Entry<Integer, byte[]> shard : shards.entrySet()) {
                    jsonGenerator.writeStartObject();
                    jsonGenerator.writeNumberField("shardPosition", shard.getKey());
                    final String base64EncodedEncryptedShard = Base64.getEncoder().encodeToString(shard.getValue());
                    jsonGenerator.writeStringField("encryptedShard", base64EncodedEncryptedShard );
                    jsonGenerator.writeEndObject();
                }
                jsonGenerator.writeEndArray();
                jsonGenerator.writeEndObject();
            }
        }
    }

    private PublicKey X509EncodedKeySpecToRsaPublicKey(final byte[] bytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    }
}
