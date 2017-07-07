package com.markgrand.cryptoShuffle;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;

/**
 * <p>Utility class for converting instances of classes in this package to and from JSON.</p>
 * Created by mark.grand on 7/5/2017.
 */
public class JsonUtil {
    private static ObjectMapper objectMapper = new ObjectMapper();

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
            jsonGenerator.writeEndObject();
        }
    }
}
