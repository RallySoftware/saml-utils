package com.ca.saml;

import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.validation.ValidationException;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.transform.TransformerException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static com.ca.saml.MockSAMLBuilder.createSAMLResponse;

public class SAMLResponseValidatorTest extends Assert {

    static {
        SAMLUtils.init();
    }

    @Test
    public void validateGoodSAMLResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        String defaultMetadata = MockSAMLBuilder.createDefaultMetadata();

        Map<String, String> attributes = defaultAttributes();
        String responseString = MockSAMLBuilder.createDefaultSAMLResponse();

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(defaultMetadata.getBytes(StandardCharsets.UTF_8));
        Response response = validator.readAndValidateSAMLResponse(responseString);

        System.out.println(SAMLUtils.toString(response));

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), 2);
        assertEquals(parsedAttributes, attributes);
    }

    @Test
    public void mismatchIssuerIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> ssoBindings = defaultSSOBindings();
        Map<String, String> attributeDefs = defaultAttributeDefinitions();
        String metdata = MockSAMLBuilder.createMetadata("sso_idpWRONG", "classpath:///saml.pkcs8", "classpath:///saml.crt", ssoBindings, attributeDefs);

        Map<String, String> attributes = defaultAttributes();
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8));
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void mismatchedCredentialsIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> attributes = defaultAttributes();
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLUtils.readClasspathResource("sample_metadata.xml"));
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void badResponseCausesException() throws FileNotFoundException, SamlException {
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLUtils.readClasspathResource("sample_metadata.xml"));
        assertThrows(() -> validator.readAndValidateSAMLResponse("toast"));
        assertThrows(() -> validator.readAndValidateSAMLResponse(null));
    }

    @Test
    public void supportAdditionalAttributes() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        Map<String, String> ssoBindings = defaultSSOBindings();
        Map<String, String> attributeDefs = defaultAttributeDefinitions();
        attributeDefs.put("locale", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");

        String metdata = MockSAMLBuilder.createMetadata("sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", ssoBindings, attributeDefs);

        Map<String, String> attributes = defaultAttributes();
        attributes.put("locale", "America/Denver");
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", true);
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8));
        Response response = validator.readAndValidateSAMLResponse(responseString);

        System.out.println(SAMLUtils.toString(response));

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), 3);
        assertEquals(parsedAttributes, attributes);
    }


    public static Map<String, String> defaultAttributes() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("email", "ue@test.com");
        attributes.put("subscription", "100");
        return attributes;
    }

    public static Map<String, String> defaultSSOBindings() {
        Map<String, String> ssoBindings = new HashMap<>();
        ssoBindings.put("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "https://rapid.ca.com:443/affwebservices/public/saml2sso");
        ssoBindings.put("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "https://rapid.ca.com:443/affwebservices/public/saml2sso");
        return ssoBindings;
    }

    public static Map<String, String> defaultAttributeDefinitions() {
        Map<String, String> attributeDefs = new HashMap<>();
        attributeDefs.put("email", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
        attributeDefs.put("subscription", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
        return attributeDefs;
    }


}
