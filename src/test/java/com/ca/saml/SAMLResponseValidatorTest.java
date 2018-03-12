package com.ca.saml;

import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.validation.ValidationException;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class SAMLResponseValidatorTest extends Assert {

    static {
        SAMLUtils.init();
    }

    @Test
    public void validateGoodSAMLResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        SAMLResponseBuilder responseBuilder = new SAMLResponseBuilder();
        SAMLMetadataBuilder metadataBuilder = new SAMLMetadataBuilder();
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metadataBuilder.createMetadata().getBytes(StandardCharsets.UTF_8));
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("email", "ue@test.com");
        attributes.put("subscription", "100");
        Response response = validator.readAndValidateSAMLResponse(responseBuilder.createSAMLResponse(attributes));

        response.getAssertions().stream()
                .flatMap(assertion -> assertion.getAttributeStatements().stream())
                .flatMap(attributeStatement -> attributeStatement.getAttributes().stream())
                .forEach(attribute -> {
                    String name = attribute.getName();
                    String content = attribute.getAttributeValues().get(0).getDOM().getTextContent();
                    System.out.println(name + ": " + content);
                });

        System.out.println(SAMLUtils.toString(response));

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        assertEquals(parsedAttributes.size(), 2);
        assertEquals(parsedAttributes.get("email"), "ue@test.com");
        assertEquals(parsedAttributes.get("subscription"), "100");
    }

}
