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

        System.out.println(SAMLUtils.toString(response));

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), 2);
        assertEquals(parsedAttributes, attributes);
    }

}
