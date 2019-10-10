package com.rallydev.saml;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.validation.ValidationException;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.transform.TransformerException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.HashMap;
import java.util.Map;

import static com.rallydev.saml.MockSAMLBuilder.createSAMLResponse;
import static com.rallydev.saml.SAMLTestUtils.defaultAttributeDefinitions;
import static com.rallydev.saml.SAMLTestUtils.defaultSSOBindings;

public class SAMLResponseValidatorTest extends Assert {

    private static final String MOCK_IDP_SAML_REDIRECT_URL = "http://localhost:8080/SingleSignOnService?RallySubscriptionId=271&TokenType=SAML";

    private static final String SP_ENTITY_ID_REQUIRED_SAML_RESPONSE_ASSERTION = "spEntityId";
    private static final String SUBSCRIPTION_REQUIRED_SAML_RESPONSE_ASSERTION = "subscription";
    private static final String EMAIL_REQUIRED_SAML_RESPONSE_ASSERTION = "email";
    private static final String TARGET_REQUIRED_SAML_RESPONSE_ASSERTION = "target";

    static {
        SAMLUtils.init();
    }

    @Test
    public void validateGoodSAMLResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        String defaultMetadata = MockSAMLBuilder.createDefaultMetadata();

        Map<String, String> attributes = getDefaultAttributes();
        String responseString = MockSAMLBuilder.createDefaultSAMLResponse();

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(defaultMetadata.getBytes(StandardCharsets.UTF_8), SAMLUtils.SP_ENTITY_ID_ALM, SAMLUtils.DEV_ALM_STRIPPED_SAML_RESPONSE_ACS_URL);
        Response response = validator.readAndValidateSAMLResponse(responseString);

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), 4);
        assertEquals(parsedAttributes, attributes);
    }

    @Test
    public void validateMockIdpSamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        validateSAMLResponse(
                SAMLUtils.SP_ENTITY_ID_ALM,
                SAMLUtils.DEV_ALM_UNSTRIPPED_SAML_RESPONSE_ACS_URL,
                "ssouser@sub265.com",
                "265",
                "/mock-idp-metadata.xml",
                "/mock-idp-samlResponse.txt");
    }

    @Test
    public void validate_Okta_exk1fm686jV32ywNB357_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        validateSAMLResponse(
                SAMLUtils.SP_ENTITY_ID_ALM,
                SAMLUtils.DEV_ALM_UNSTRIPPED_SAML_RESPONSE_ACS_URL,
                "ssouser1@test.com",
                "100",
                "/www.okta.com-exk1fm686jV32ywNB357-metadata.xml",
                "/www.okta.com-exk1fm686jV32ywNB357-samlResponse.txt");
    }

    private void validateSAMLResponse(
            String spEntityId,
            String recipient,
            String username,
            String subscription,
            String metadataPath,
            String samlResponsePath) throws IOException, SamlException, MessageDecodingException, ValidationException {
        String idpMetadata = SAMLTestUtils.getResourceFileContentsAsString(metadataPath);
        String responseString = SAMLTestUtils.getResourceFileContentsAsString(samlResponsePath);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(idpMetadata.getBytes(StandardCharsets.UTF_8), spEntityId, recipient);
        Response response = validator.readAndValidateSAMLResponse(responseString, false);

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        Map<String, String> requiredAttributes = parsedAttributes.
                entrySet().stream()
                .filter(x -> Arrays.asList(
                        SP_ENTITY_ID_REQUIRED_SAML_RESPONSE_ASSERTION,
                        SUBSCRIPTION_REQUIRED_SAML_RESPONSE_ASSERTION,
                        EMAIL_REQUIRED_SAML_RESPONSE_ASSERTION,
                        TARGET_REQUIRED_SAML_RESPONSE_ASSERTION).contains(x.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        assertEquals(requiredAttributes.size(), 4);

        Map<String, String> expectedAttributes = getExpectedAttributes(username, subscription, spEntityId, recipient);
        assertEquals(requiredAttributes, expectedAttributes);
    }

    @Test
    public void modifyRedirectUrlDisabled()  {
        String modifiedRedirectUrl = SAMLUtils.modifyRedirectUrlForDevTestSSOFederationServer(MOCK_IDP_SAML_REDIRECT_URL, SAMLUtils.DEV_ZUUL_SAML_RESPONSE_ACS_URL, SAMLUtils.SP_ENTITY_ID_ZUUL, false);
        assertEquals(MOCK_IDP_SAML_REDIRECT_URL, modifiedRedirectUrl);
    }

    @Test
    public void modifyRedirectUrlEnabled()  {
        String modifiedRedirectUrl = SAMLUtils.modifyRedirectUrlForDevTestSSOFederationServer(MOCK_IDP_SAML_REDIRECT_URL, SAMLUtils.DEV_ZUUL_SAML_RESPONSE_ACS_URL, SAMLUtils.SP_ENTITY_ID_ZUUL, true);
        assertNotEquals(MOCK_IDP_SAML_REDIRECT_URL, modifiedRedirectUrl);
        assertNotNull(SAMLTestUtils.getParamFromUrl(modifiedRedirectUrl, SAMLUtils.SAML_REQUEST_PARAM_NAME));
    }

    @Test
    public void mismatchIssuerIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> ssoBindings = defaultSSOBindings();
        Map<String, String> attributeDefs = defaultAttributeDefinitions();
        String metdata = MockSAMLBuilder.createMetadata("sso_idpWRONG", "classpath:///saml.pkcs8", "classpath:///saml.crt", ssoBindings, attributeDefs);

        Map<String, String> attributes = getDefaultAttributes();
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8), SAMLUtils.SP_ENTITY_ID_ALM, SAMLUtils.DEV_ALM_STRIPPED_SAML_RESPONSE_ACS_URL);
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void mismatchedCredentialsIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> attributes = getDefaultAttributes();
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLUtils.readClasspathResource("sample_metadata.xml"), SAMLUtils.SP_ENTITY_ID_ALM, SAMLUtils.DEV_ALM_STRIPPED_SAML_RESPONSE_ACS_URL);
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void badResponseCausesException() throws FileNotFoundException, SamlException {
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLUtils.readClasspathResource("sample_metadata.xml"), SAMLUtils.SP_ENTITY_ID_ALM, SAMLUtils.DEV_ALM_STRIPPED_SAML_RESPONSE_ACS_URL);
        assertThrows(() -> validator.readAndValidateSAMLResponse("toast"));
        assertThrows(() -> validator.readAndValidateSAMLResponse(null));
    }

    @Test
    public void spEnitityIdMistachCausesException() throws SamlException {
        assertThrowsErrorWithAttributes("spEntityId", "wrongSpId");
    }

    @Test
    public void recipientMistachCausesException() throws SamlException {
        assertThrowsErrorWithAttributes("target", SAMLUtils.DEV_ALM_STRIPPED_OPEN_TOKEN_ACS_URL);
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
        Map attributes = getDefaultAttributes();
        attributes.put(key, value);
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLUtils.readClasspathResource("sample_metadata.xml"), SAMLUtils.SP_ENTITY_ID_ALM, SAMLUtils.DEV_ALM_STRIPPED_SAML_RESPONSE_ACS_URL);
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);
        assertThrows(() -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void supportAdditionalAttributes() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        Map<String, String> ssoBindings = defaultSSOBindings();
        Map<String, String> attributeDefs = defaultAttributeDefinitions();
        attributeDefs.put("locale", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");

        String metdata = MockSAMLBuilder.createMetadata("sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", ssoBindings, attributeDefs);

        Map<String, String> attributes = getDefaultAttributes();
        attributes.put("locale", "America/Denver");
        String responseString = createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", true);
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8), SAMLUtils.SP_ENTITY_ID_ALM, SAMLUtils.DEV_ALM_STRIPPED_SAML_RESPONSE_ACS_URL);
        Response response = validator.readAndValidateSAMLResponse(responseString);


        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), 5);
        assertEquals(parsedAttributes, attributes);
    }


    public static Map<String, String> getDefaultAttributes() {
        return getExpectedAttributes("ue@test.com", "100", SAMLUtils.SP_ENTITY_ID_ALM, SAMLUtils.DEV_ALM_STRIPPED_SAML_RESPONSE_ACS_URL);
    }

    public static Map<String, String> getExpectedAttributes(String email, String subscription, String spEntityId, String target) {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put(EMAIL_REQUIRED_SAML_RESPONSE_ASSERTION, email);
        attributes.put(SUBSCRIPTION_REQUIRED_SAML_RESPONSE_ASSERTION, subscription);
        attributes.put(SP_ENTITY_ID_REQUIRED_SAML_RESPONSE_ASSERTION, spEntityId);
        attributes.put(TARGET_REQUIRED_SAML_RESPONSE_ASSERTION, target);
        return attributes;
    }
}
