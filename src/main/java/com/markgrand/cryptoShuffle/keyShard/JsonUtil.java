package com.markgrand.cryptoShuffle.keyShard;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * <p>Utility class for converting instances of classes in this package to and from JSON.</p>
 * Created by mark.grand on 7/5/2017.
 */
public class JsonUtil {
    private final static ObjectMapper objectMapper = new ObjectMapper();
    public static final String ENCRYPTION_ALGORITHM_NAME = "encryptionAlgorithm";
    public static final String GROUPS_NAME = "groups";
    public static final String SHARD_COUNT_NAME = "shardCount";
    public static final String UUID_NAME = "uuid";
    public static final String VERSION_NAME = "version";

    static {
        final SimpleModule module = new SimpleModule("KeyShardSet");
        module.addSerializer(KeyShardSet.class, new KeyShardSetSerializer());
        module.addDeserializer(KeyShardSet.class, new KeyShardSetDeserializer());
        module.addSerializer(KeyShardSet.KeyShardGroup.class, new KeyShardGroupSerializer());
        objectMapper.registerModule(module);
    }

    /**
     * Convert a {@link KeyShardSet} to a JSON object.
     *
     * @param keyShardSet the {@code KeyShardSet} to be converted to JSON
     * @return a JSON object that represents the given {@link KeyShardSet}
     */
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
            jsonGenerator.writeStringField(ENCRYPTION_ALGORITHM_NAME, value.getEncryptionAlgorithm().name());
            jsonGenerator.writeStringField("uuid", value.getUuid().toString());
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
                final Map<Integer, EncryptedShard> shards = value.getEncryptedShardsForKey(publicKey);
                Base64.Encoder base64Encoder = Base64.getEncoder();
                for (Map.Entry<Integer, EncryptedShard> shard : shards.entrySet()) {
                    serializeEncryptedShard(jsonGenerator, base64Encoder, shard);
                }
                jsonGenerator.writeEndArray();
                jsonGenerator.writeEndObject();
            }
        }

        private static void serializeEncryptedShard(JsonGenerator jsonGenerator, Base64.Encoder base64Encoder, Map.Entry<Integer, EncryptedShard> shard) throws IOException {
            jsonGenerator.writeStartObject();
            jsonGenerator.writeNumberField("shardPosition", shard.getKey());
            final String base64EncodedEncryptedShard = base64Encoder.encodeToString(shard.getValue().getEncryptedShardValue());
            jsonGenerator.writeStringField("encryptedShard", base64EncodedEncryptedShard);
            final SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm = shard.getValue().getSymmetricEncryptionAlgorithm();
            if (symmetricEncryptionAlgorithm != null) {
                jsonGenerator.writeStringField("symmetricEncryption", symmetricEncryptionAlgorithm.name());
            }
            final byte[] encryptedSymmetricKey = shard.getValue().getEncryptedSymmetricKey();
            if (encryptedSymmetricKey != null) {
                final String base64EncryptedKey = base64Encoder.encodeToString(encryptedSymmetricKey);
                jsonGenerator.writeStringField("encryptedSymmetricKey", base64EncryptedKey);
            }
            jsonGenerator.writeEndObject();
        }
    }

    /**
     * Create a {@link KeyShardSet} that matches the given JSON.
     *
     * @param jsonNode The JSON to use for building the {@link KeyShardSet}.
     * @return the new {@link KeyShardSet}
     * @throws JsonProcessingException If there is a problem processing the JSON.
     */
    public static KeyShardSet jsonToKeyShardSet(final JsonNode jsonNode) throws JsonProcessingException {
        return objectMapper.treeToValue(jsonNode, KeyShardSet.class);
    }

    public static class KeyShardSetDeserializer extends StdDeserializer<KeyShardSet> {
        public KeyShardSetDeserializer() {
            this(null);
        }

        public KeyShardSetDeserializer(Class<?> vc) {
            super(vc);
        }

        @Override
        public KeyShardSet deserialize(final JsonParser jp, final DeserializationContext context) throws IOException {
            JsonNode node = jp.getCodec().readTree(jp);
            String version = deserializeVersion(node);
            switch (version) {
                case "1.0":
                    deserialize1_0(node);
                    break;
                default:
                    throw new RuntimeException("Value of " + VERSION_NAME + " is \"" + version + "\" but must be \"1.0\"");
            }
            //KeyShardSet.newBuilder();
            // TODO finish this
            return null;
        }

        private void deserialize1_0(final JsonNode node) {
            final AsymmetricEncryptionAlgorithms encryptionAlgorithm = deserializeAsymmetricEncryptionAlgorithm(node);
            final UUID uuid = deserializeUuid(node);
            final int shardCount = deserializeShardCount(node);
            final ArrayNode groups = getGroups(node);
        }

        private ArrayNode getGroups(JsonNode node) {
            final JsonNode valueNode = requireValue(node, GROUPS_NAME);
            ensureType(valueNode, JsonNodeType.ARRAY, GROUPS_NAME);
            final ArrayNode groups = (ArrayNode)valueNode;
            if (groups.size() == 0) {
                throw new RuntimeException("Value of groups is an empty array. At least one group is required.");
            }
            return groups;
        }

        private int deserializeShardCount(JsonNode node) {
            int shardCount = requireIntValue(node, SHARD_COUNT_NAME);
            if (shardCount < 1) {
                throw new RuntimeException("Value of " + SHARD_COUNT_NAME + " must be greater than 0.");
            }
            return shardCount;
        }

        private UUID deserializeUuid(JsonNode node) {
            String uuidString = requireStringValue(node, UUID_NAME);
            return UUID.fromString(uuidString);
        }

        private static String deserializeVersion(JsonNode node) {
            return requireStringValue(node, VERSION_NAME);
        }

        private static int requireIntValue(final JsonNode node, final String fieldName) {
            final JsonNode valueNode = requireValue(node, fieldName);
            ensureType(valueNode, JsonNodeType.NUMBER, fieldName);
            if (!valueNode.canConvertToInt()) {
                throw new RuntimeException("Value of " + fieldName + " must be an integer: " + node);
            }
            return valueNode.asInt();
        }

        private static String requireStringValue(final JsonNode node, final String fieldName) {
            final JsonNode valueNode = requireValue(node, fieldName);
            ensureType(valueNode, JsonNodeType.STRING, fieldName);
            return valueNode.asText();
        }

        private static void ensureType(final JsonNode node, final JsonNodeType type, final String fieldName) {
            if (!type.equals(node.getNodeType())) {
                String msg = "Value of " + fieldName + " must be specified as a string but was specified as a " + type.name();
                throw new RuntimeException(msg);
            }
        }

        private static JsonNode requireValue(final JsonNode node, final String fieldName) {
            final JsonNode valueNode = node.get(fieldName);
            if (valueNode == null) {
                String msg = "Value of " + fieldName + " must be specified in JSON for a KeyShardSet: " + node.toString();
                throw new RuntimeException(msg);
            }
            return valueNode;
        }

        private static AsymmetricEncryptionAlgorithms  deserializeAsymmetricEncryptionAlgorithm(JsonNode node) {
            final String encryptionAlgorithmValue = node.get(ENCRYPTION_ALGORITHM_NAME).asText();
            try {
                return AsymmetricEncryptionAlgorithms.valueOf(encryptionAlgorithmValue);
            } catch (IllegalArgumentException e) {
                String msg = "Unsupported value for " + ENCRYPTION_ALGORITHM_NAME + ": " + encryptionAlgorithmValue
                        + "\nSupported values are " + Arrays.toString(AsymmetricEncryptionAlgorithms.values());
                throw new RuntimeException(msg);
            }
        }
    }

//    private static PublicKey X509EncodedKeySpecToRsaPublicKey(final byte[] bytes)
//            throws NoSuchAlgorithmException, InvalidKeySpecException {
//        return KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(bytes));
//    }
}
