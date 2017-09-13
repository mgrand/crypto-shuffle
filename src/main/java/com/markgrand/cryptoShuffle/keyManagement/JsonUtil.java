package com.markgrand.cryptoShuffle.keyManagement;

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
import com.markgrand.cryptoShuffle.keyManagement.AsymmetricEncryptionAlgorithm;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * <p>Utility class for converting instances of classes in this package to and from JSON.</p>
 * Created by mark.grand on 7/5/2017.
 */
public class JsonUtil {
    private final static ObjectMapper objectMapper = new ObjectMapper();
    public static final String ENCRYPTED_SHARD_NAME = "encryptedShard";
    public static final String ENCRYPTED_SYMMETRIC_KEY_NAME = "encryptedSymmetricKey";
    public static final String ENCRYPTION_ALGORITHM_NAME = "encryptionAlgorithm";
    public static final String GROUPS_NAME = "groups";
    public static final String KEY_MAP_NAME = "keyMap";
    public static final String PUBLIC_KEY_NAME = "publicKey";
    public static final String QUORUM_SIZE_NAME = "quorumSize";
    public static final String SHARD_COUNT_NAME = "shardCount";
    public static final String SHARD_POSITION_NAME = "shardPosition";
    public static final String SYMMETRIC_ENCRYPTION_NAME = "symmetricEncryption";
    public static final String UUID_NAME = "uuid";
    public static final String VERSION1_0 = "1.0";
    public static final String VERSION_NAME = "version";
    public static final String SHARDS_NAME = "shards";

    static {
        @NotNull final SimpleModule module = new SimpleModule("KeyShardSet");
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
        public void serialize(@NotNull KeyShardSet value, @NotNull JsonGenerator jsonGenerator, SerializerProvider provider) throws IOException {
            jsonGenerator.writeStartObject();
            jsonGenerator.writeStringField(VERSION_NAME, VERSION1_0);
            jsonGenerator.writeStringField(ENCRYPTION_ALGORITHM_NAME, value.getEncryptionAlgorithm().name());
            jsonGenerator.writeStringField(UUID_NAME, value.getUuid().toString());
            jsonGenerator.writeNumberField(SHARD_COUNT_NAME, value.getShardCount());
            jsonGenerator.writeArrayFieldStart(GROUPS_NAME);
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
        public void serialize(@NotNull KeyShardSet.KeyShardGroup value,
                              @NotNull JsonGenerator jsonGenerator, SerializerProvider provider) throws IOException {
            jsonGenerator.writeStartObject();
            jsonGenerator.writeNumberField(QUORUM_SIZE_NAME, value.getQuorumSize());
            jsonGenerator.writeArrayFieldStart(KEY_MAP_NAME);
            serializeGroupPublicKeys(value, jsonGenerator);
            jsonGenerator.writeEndArray();
            jsonGenerator.writeEndObject();
        }

        private void serializeGroupPublicKeys(@NotNull KeyShardSet.KeyShardGroup value, @NotNull JsonGenerator jsonGenerator) throws IOException {
            for (@NotNull PublicKey publicKey : value.getKeys()) {
                jsonGenerator.writeStartObject();
                final String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                jsonGenerator.writeStringField(PUBLIC_KEY_NAME, encodedPublicKey);
                jsonGenerator.writeArrayFieldStart(SHARDS_NAME);
                @NotNull final Map<Integer, EncryptedShard> shards = value.getEncryptedShardsForKey(publicKey);
                Base64.Encoder base64Encoder = Base64.getEncoder();
                for (@NotNull Map.Entry<Integer, EncryptedShard> shard : shards.entrySet()) {
                    serializeEncryptedShard(jsonGenerator, base64Encoder, shard);
                }
                jsonGenerator.writeEndArray();
                jsonGenerator.writeEndObject();
            }
        }

        private static void serializeEncryptedShard(@NotNull JsonGenerator jsonGenerator, @NotNull Base64.Encoder base64Encoder, @NotNull Map.Entry<Integer, EncryptedShard> shard) throws IOException {
            jsonGenerator.writeStartObject();
            jsonGenerator.writeNumberField(SHARD_POSITION_NAME, shard.getKey());
            final String base64EncodedEncryptedShard = base64Encoder.encodeToString(shard.getValue().getEncryptedShardValue());
            jsonGenerator.writeStringField(ENCRYPTED_SHARD_NAME, base64EncodedEncryptedShard);
            final SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm = shard.getValue().getSymmetricEncryptionAlgorithm();
            if (symmetricEncryptionAlgorithm != null) {
                jsonGenerator.writeStringField(SYMMETRIC_ENCRYPTION_NAME, symmetricEncryptionAlgorithm.name());
            }
            final byte[] encryptedSymmetricKey = shard.getValue().getEncryptedSymmetricKey();
            if (encryptedSymmetricKey != null) {
                final String base64EncryptedKey = base64Encoder.encodeToString(encryptedSymmetricKey);
                jsonGenerator.writeStringField(ENCRYPTED_SYMMETRIC_KEY_NAME, base64EncryptedKey);
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
    public static KeyShardSet jsonToKeyShardSet(@NotNull final JsonNode jsonNode) throws JsonProcessingException {
        return objectMapper.treeToValue(jsonNode, KeyShardSet.class);
    }

    public static class KeyShardSetDeserializer extends StdDeserializer<KeyShardSet> {
        public KeyShardSetDeserializer() {
            this(null);
        }

        public KeyShardSetDeserializer(Class<?> vc) {
            super(vc);
        }

        @NotNull
        @Override
        public KeyShardSet deserialize(@NotNull final JsonParser jp, final DeserializationContext context) throws IOException {
            JsonNode node = jp.getCodec().readTree(jp);
            String version = deserializeVersion(node);
            switch (version) {
                case VERSION1_0:
                    return deserialize1_0(node);
                default:
                    throw new RuntimeException("Value of " + VERSION_NAME + " is \"" + version + "\" but must be \"1.0\"");
            }
        }

        private KeyShardSet deserialize1_0(@NotNull final JsonNode node) {
            @NotNull final UUID uuid = deserializeUuid(node);
            final int shardCount = deserializeShardCount(node);
            final AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm = deserializeAsymmetricEncryptionAlgorithm(node);
            @NotNull final ArrayNode groups = getGroups(node);
            @NotNull final ArrayList<KeyShardSet.KeyShardGroup> keyShardGroups = new ArrayList<>();
            for (@NotNull JsonNode group : groups) {
                final int quorumSize = deserializeQuorumSize(group);
                @NotNull final Map<PublicKey, Map<Integer, EncryptedShard>> keyMap = deserializeKeyMap(group);
                keyShardGroups.add(new KeyShardSet.KeyShardGroup(quorumSize, keyMap));
            }
            return new KeyShardSet(keyShardGroups, shardCount, uuid, asymmetricEncryptionAlgorithm);
        }

        private int deserializeQuorumSize(@NotNull JsonNode group) {
            return deserializePositiveInt(group, QUORUM_SIZE_NAME);
        }

        @NotNull
        private Map<PublicKey,Map<Integer,EncryptedShard>> deserializeKeyMap(@NotNull JsonNode group) {
            @NotNull final ArrayNode keyMapArray = requireArrayValue(group, KEY_MAP_NAME);
            @NotNull final Map<PublicKey,Map<Integer,EncryptedShard>> keyMap = new HashMap<>();
            for(@NotNull JsonNode key : keyMapArray) {
                final byte[] publicKeyBytes = base64StringToBytes(requireStringValue(key, PUBLIC_KEY_NAME));
                final PublicKey publicKey = bytesToPublicKey(publicKeyBytes);
                @NotNull final Map<Integer,EncryptedShard> shardMap = deserializeShardMap(publicKeyBytes, key);
                keyMap.put(publicKey, shardMap);
            }
            return keyMap;
        }

        @NotNull
        private Map<Integer,EncryptedShard> deserializeShardMap(final byte[] publicKeyBytes, @NotNull final JsonNode key) {
            @NotNull final Map<Integer, EncryptedShard> shardMap = new HashMap<>();
            @NotNull final ArrayNode shardMapArray = requireArrayValue(key, SHARDS_NAME);
            for (@NotNull JsonNode shard: shardMapArray) {
                final int shardPosition = requireIntValue(shard, SHARD_POSITION_NAME);
                @NotNull final EncryptedShard encryptedShard = deserializeEncryptedShard(publicKeyBytes, shard);
                shardMap.put(shardPosition, encryptedShard);
            }
            return shardMap;
        }

        private EncryptedShard deserializeEncryptedShard(final byte[] publicKeyBytes, @NotNull final JsonNode shard) {
            byte[] encryptedKeyShardBytes = base64StringToBytes(requireStringValue(shard, ENCRYPTED_SHARD_NAME));
            final JsonNode symmetricKeyNode = shard.get(ENCRYPTED_SYMMETRIC_KEY_NAME);
            final JsonNode symmetricEncryptionAlgorithmNode = shard.get(SYMMETRIC_ENCRYPTION_NAME);
            if (symmetricKeyNode == null && symmetricEncryptionAlgorithmNode == null) {
                return new EncryptedShard(publicKeyBytes, encryptedKeyShardBytes);
            } else if (symmetricKeyNode != null && symmetricEncryptionAlgorithmNode != null) {
                byte[] encryptedSymmetricKey = base64StringToBytes(symmetricKeyNode.asText());
                SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm.valueOf(symmetricEncryptionAlgorithmNode.asText());
                return new EncryptedShard(publicKeyBytes, encryptedKeyShardBytes, symmetricEncryptionAlgorithm, encryptedSymmetricKey);
            } else {
                @NotNull final String msg = ENCRYPTED_SYMMETRIC_KEY_NAME + " and " + SYMMETRIC_ENCRYPTION_NAME
                                           + " must either be both specified or both not specified " + shard.toString();
                throw new RuntimeException(msg);
            }
        }

        @NotNull
        private static ArrayNode getGroups(@NotNull JsonNode node) {
            @NotNull final ArrayNode groups = requireArrayValue(node, GROUPS_NAME);
            if (groups.size() == 0) {
                throw new RuntimeException("Value of groups is an empty array. At least one group is required.");
            }
            return groups;
        }

        @NotNull
        private static ArrayNode requireArrayValue(@NotNull final JsonNode node, final String fieldName) {
            final JsonNode valueNode = requireValue(node, fieldName);
            ensureType(valueNode, JsonNodeType.ARRAY, fieldName);
            return (ArrayNode)valueNode;
        }

        private static int deserializeShardCount(@NotNull JsonNode node) {
            return deserializePositiveInt(node, SHARD_COUNT_NAME);
        }

        private static int deserializePositiveInt(@NotNull final JsonNode node, final String fieldName) {
            int value = requireIntValue(node, fieldName);
            if (value < 1) {
                throw new RuntimeException("Value of " + fieldName + " must be greater than 0.");
            }
            return value;
        }

        private static UUID deserializeUuid(@NotNull JsonNode node) {
            String uuidString = requireStringValue(node, UUID_NAME);
            return UUID.fromString(uuidString);
        }

        private static String deserializeVersion(@NotNull JsonNode node) {
            return requireStringValue(node, VERSION_NAME);
        }

        private static int requireIntValue(@NotNull final JsonNode node, final String fieldName) {
            final JsonNode valueNode = requireValue(node, fieldName);
            ensureType(valueNode, JsonNodeType.NUMBER, fieldName);
            if (!valueNode.canConvertToInt()) {
                throw new RuntimeException("Value of " + fieldName + " must be an integer: " + node);
            }
            return valueNode.asInt();
        }

        private static String requireStringValue(@NotNull final JsonNode node, final String fieldName) {
            final JsonNode valueNode = requireValue(node, fieldName);
            ensureType(valueNode, JsonNodeType.STRING, fieldName);
            return valueNode.asText();
        }

        private static void ensureType(@NotNull final JsonNode node, @NotNull final JsonNodeType type, final String fieldName) {
            if (!type.equals(node.getNodeType())) {
                @NotNull String msg = "Value of " + fieldName + " must be specified as a string but was specified as a " + type.name();
                throw new RuntimeException(msg);
            }
        }

        private static JsonNode requireValue(@NotNull final JsonNode node, final String fieldName) {
            final JsonNode valueNode = node.get(fieldName);
            if (valueNode == null) {
                @NotNull String msg = "Value of " + fieldName + " must be specified in JSON for a KeyShardSet: " + node.toString();
                throw new RuntimeException(msg);
            }
            return valueNode;
        }

//        public static PublicKey stringToPublicKey(String keyString){
//            return bytesToPublicKey(base64StringToBytes(keyString));
//        }

         static PublicKey bytesToPublicKey(@NotNull byte[] keyBytes){
            try{
                @NotNull X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(keyBytes);
                @NotNull KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(X509publicKey);
            }
            catch(Exception e){
                throw new RuntimeException("Problem converting string to PublicKey: " + bytesToBase64String(keyBytes), e);
            }
        }

        private static AsymmetricEncryptionAlgorithm deserializeAsymmetricEncryptionAlgorithm(@NotNull JsonNode node) {
            final String encryptionAlgorithmValue = node.get(ENCRYPTION_ALGORITHM_NAME).asText();
            try {
                return AsymmetricEncryptionAlgorithm.valueOf(encryptionAlgorithmValue);
            } catch (IllegalArgumentException e) {
                @NotNull String msg = "Unsupported value for " + ENCRYPTION_ALGORITHM_NAME + ": " + encryptionAlgorithmValue
                        + "\nSupported values are " + Arrays.toString(AsymmetricEncryptionAlgorithm.values());
                throw new RuntimeException(msg);
            }
        }

        private static byte[] base64StringToBytes(@NotNull String keyString) {
            return Base64.getDecoder().decode(keyString);
        }

        private static String bytesToBase64String(byte[] bytes) {
            return Base64.getEncoder().encodeToString(bytes);
        }
    }

//    private static PublicKey X509EncodedKeySpecToRsaPublicKey(final byte[] bytes)
//            throws NoSuchAlgorithmException, InvalidKeySpecException {
//        return KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(bytes));
//    }
}