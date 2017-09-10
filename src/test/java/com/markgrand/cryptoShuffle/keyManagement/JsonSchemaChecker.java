package com.markgrand.cryptoShuffle.keyManagement;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.fge.jsonschema.core.report.ProcessingReport;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.github.fge.jsonschema.processors.syntax.SyntaxValidator;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;

/**
 * <p>
 * This checks to make sure that the file KeyShardSet.json contains a syntactically valid JSON schema.
 * </p>
 * Created by mark.grand on 7/5/2017.
 */
public class JsonSchemaChecker implements JsonSchemaConstants {

    @Test
    public void checkJsonSchema() throws Exception {
        File file = new File(JSON_SCHEMA_FILE_PATH);
        System.out.println("Validating syntax of " + file.getAbsolutePath());
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(file);
        SyntaxValidator syntaxValidator = JsonSchemaFactory.byDefault().getSyntaxValidator();
        ProcessingReport report = syntaxValidator.validateSchema(jsonNode);
        System.out.println(report);
        Assert.assertTrue(syntaxValidator.schemaIsValid(jsonNode));
    }
}
