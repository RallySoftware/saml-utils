package com.rallydev.saml;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLException;
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

import static com.rallydev.saml.MockSAMLBuilder.createSAMLResponse;
import static com.rallydev.saml.SAMLTestUtils.defaultAttributeDefinitions;
import static com.rallydev.saml.SAMLTestUtils.defaultSSOBindings;

public class SAMLResponseValidatorTest extends Assert {

    static {
        SAMLUtils.init();
    }

    @Test
    public void validateGoodSAMLResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        String defaultMetadata = MockSAMLBuilder.createDefaultMetadata();

        Map<String, String> attributes = defaultAttributes();
        String responseString = MockSAMLBuilder.createDefaultSAMLResponse();

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(defaultMetadata.getBytes(StandardCharsets.UTF_8), "alm_sp", "http://localhost:7001/j_saml_security_check");
        Response response = validator.readAndValidateSAMLResponse(responseString);


        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), 4);
        assertEquals(parsedAttributes, attributes);
    }

    @Test
    public void mismatchIssuerIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> ssoBindings = defaultSSOBindings();
        Map<String, String> attributeDefs = defaultAttributeDefinitions();
        String metdata = MockSAMLBuilder.createMetadata("sso_idpWRONG", "classpath:///saml.pkcs8", "classpath:///saml.crt", ssoBindings, attributeDefs);

        Map<String, String> attributes = defaultAttributes();
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8), "alm_sp", "http://localhost:7001/j_saml_security_check");
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void mismatchedCredentialsIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> attributes = defaultAttributes();
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLUtils.readClasspathResource("sample_metadata.xml"), "alm_sp", "http://localhost:7001/j_saml_security_check");
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void badResponseCausesException() throws FileNotFoundException, SamlException {
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLUtils.readClasspathResource("sample_metadata.xml"), "alm_sp", "http://localhost:7001/j_saml_security_check");
        assertThrows(() -> validator.readAndValidateSAMLResponse("toast"));
        assertThrows(() -> validator.readAndValidateSAMLResponse(null));
    }

    @Test
    public void spEnitityIdMistachCausesException() throws SamlException {
        assertThrowsErrorWithAttributes("spEntityId", "wrongSpId");
    }

    @Test
    public void recipientMistachCausesException() throws SamlException {
        assertThrowsErrorWithAttributes("target", "http://localhost:7001/j_sso_security_check");
    }

    @Test
    public void missingAuthnStateMentCausesException() throws SamlException {
        assertThrowsErrorWithAttributes("doNotCreateAuthnStatement", true);
    }

    @Test
    public void subjectAfterDateThrowsError() throws SamlException {
        assertThrowsErrorWithAttributes("subjectNotOnOrAfterDate", new DateTime().minusDays(1));
    }

    @Test
    public void assertionAfterDateThrowsError() throws SamlException {
        assertThrowsErrorWithAttributes("assertionNotOnOrAfterDate", new DateTime().minusDays(1));
    }

    @Test
    public void assertionDateBeforeThrowsError() throws SamlException {
        assertThrowsErrorWithAttributes("assertionNotBeforeDate", new DateTime().plusDays(1));

    }

    public void assertThrowsErrorWithAttributes(String key, Object value) throws SamlException{
        Map attributes = defaultAttributes();
        attributes.put(key, value);
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLUtils.readClasspathResource("sample_metadata.xml"), "alm_sp", "http://localhost:7001/j_saml_security_check");
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);
        assertThrows(() -> validator.readAndValidateSAMLResponse(responseString));
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
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8), "alm_sp", "http://localhost:7001/j_saml_security_check");
        Response response = validator.readAndValidateSAMLResponse(responseString);


        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), 5);
        assertEquals(parsedAttributes, attributes);
    }


    public static Map<String, String> defaultAttributes() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("email", "ue@test.com");
        attributes.put("subscription", "100");
        attributes.put("spEntityId", "alm_sp");
        attributes.put("target", "http://localhost:7001/j_saml_security_check");
        return attributes;
    }




}
