package com.markgrand.cryptoShuffle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * <p>Utility class for converting instances of classes in this package to and from JSON.</p>
 * Created by mark.grand on 7/5/2017.
 */
public class JsonUtil {
    private static ObjectMapper objectMapper = new ObjectMapper();

    public static JsonNode keyShardSetToJson(final KeyShardSet keyShardSet) {

        return objectMapper.valueToTree(keyShardSet);
    }
}
