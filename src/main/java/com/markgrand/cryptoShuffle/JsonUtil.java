package com.markgrand.cryptoShuffle;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;

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
            jsonGenerator.writeStringField("uuid", value.getGuid().toString());
            jsonGenerator.writeNumberField("shardCount", value.getShardCount());
            jsonGenerator.writeArrayFieldStart("groups");
            for (KeyShardSet.KeyShardGroup group: value.getGroups()) {
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
            jsonGenerator.writeEndObject();
        }
    }
}
