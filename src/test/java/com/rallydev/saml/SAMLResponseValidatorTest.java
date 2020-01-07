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
import java.util.List;
import java.util.Map;

import static com.rallydev.saml.MockSAMLBuilder.createSAMLResponseWithDefaultKey;
import static com.rallydev.saml.SAMLTestUtils.defaultAttributeDefinitions;
import static com.rallydev.saml.SAMLTestUtils.defaultSSOBindings;

public class SAMLResponseValidatorTest extends Assert {

    private static final String MOCK_IDP_SAML_REDIRECT_URL = "http://localhost:8080/SingleSignOnService?RallySubscriptionId=271&TokenType=SAML";

    private static final String DEV_ZUUL_SAML_RESPONSE_ACS_URL = "http://localhost:3000/login/sso";

    static {
        SAMLUtils.init();
    }

    @Test
    public void validateGoodSAMLResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        String defaultMetadata = MockSAMLBuilder.createDefaultMetadata();

        Map<String, String> defaultAttributes = getDefaultAttributes();
        String responseString = MockSAMLBuilder.createDefaultSAMLResponse();

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(defaultMetadata.getBytes(StandardCharsets.UTF_8));
        Response response = validator.readAndValidateSAMLResponse(responseString);

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), defaultAttributes.size());
        assertEquals(parsedAttributes, defaultAttributes);
    }

    @Test
    public void validateMockIdpSamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        validateSAMLResponse(
                "ssouser@sub265.com",
                "265",
                "/mock-idp-metadata.xml",
                "/mock-idp-samlResponse.txt");
    }

    @Test
    public void validate_Okta_exknyz5bdks93pPNy0h7_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        validateSAMLResponse(
                "ssouser1@test.com",
                "100",
                "/www.okta.com-exknyz5bdks93pPNy0h7-metadata.xml",
                "/www.okta.com-exknyz5bdks93pPNy0h7-samlResponse.txt"
        );
    }

    @Test
    public void validate_Okta_exk1fm686jV32ywNB357_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        validateSAMLResponse(
                "ssouser1@test.com",
                "313",
                "/www.okta.com-exk1fm686jV32ywNB357-metadata.xml",
                "/www.okta.com-exk1fm686jV32ywNB357-samlResponse.txt");
    }

    @Test
    public void validate_Okta_exko9ji5yhMifwM6G0h7_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        validateSAMLResponse(
                "ssouser1@test.com",
                "148",
                "/www.okta.com-exko9ji5yhMifwM6G0h7-metadata.xml",
                "/www.okta.com-exko9ji5yhMifwM6G0h7-samlResponse.txt");
    }

    @Test
    public void validate_Okta_exkoya2eyoW7S7OW80h7_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        validateSAMLResponse(
                "ssouser1@test.com",
                "163",
                "/www.okta.com-exkoya2eyoW7S7OW80h7-metadata.xml",
                "/www.okta.com-exkoya2eyoW7S7OW80h7-samlResponse.txt");
    }

    private List<String> getRequiredAssertionKeys() {
        return Arrays.asList(
                SAMLResponseValidator.SUBSCRIPTION_REQUIRED_SAML_RESPONSE_ASSERTION,
                SAMLResponseValidator.EMAIL_REQUIRED_SAML_RESPONSE_ASSERTION);
    }

    private void validateSAMLResponse(
            String username,
            String subscription,
            String metadataPath,
            String samlResponsePath) throws IOException, SamlException, MessageDecodingException, ValidationException {
        String idpMetadata = SAMLTestUtils.getResourceFileContentsAsString(metadataPath);
        String responseString = SAMLTestUtils.getResourceFileContentsAsString(samlResponsePath);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(idpMetadata.getBytes(StandardCharsets.UTF_8));
        Response response = validator.readAndValidateSAMLResponse(responseString, false);

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        Map<String, String> requiredAttributes = parsedAttributes.
                entrySet().stream()
                .filter(x -> getRequiredAssertionKeys().contains(x.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        assertEquals(requiredAttributes.size(), getRequiredAssertionKeys().size());

        Map<String, String> expectedAttributes = getExpectedAttributes(username, subscription);
        assertEquals(requiredAttributes, expectedAttributes);
    }

    @Test
    public void modifyRedirectUrlDisabled()  {
        String modifiedRedirectUrl = SAMLUtils.modifyRedirectUrlForDevTestSSOFederationServer(MOCK_IDP_SAML_REDIRECT_URL,  DEV_ZUUL_SAML_RESPONSE_ACS_URL, SAMLUtils.SP_ENTITY_ID_ZUUL, false);
        assertEquals(MOCK_IDP_SAML_REDIRECT_URL, modifiedRedirectUrl);
    }

    @Test
    public void modifyRedirectUrlEnabled()  {
        String modifiedRedirectUrl = SAMLUtils.modifyRedirectUrlForDevTestSSOFederationServer(MOCK_IDP_SAML_REDIRECT_URL, DEV_ZUUL_SAML_RESPONSE_ACS_URL, SAMLUtils.SP_ENTITY_ID_ZUUL, true);
        assertNotEquals(MOCK_IDP_SAML_REDIRECT_URL, modifiedRedirectUrl);
        assertNotNull(SAMLTestUtils.getParamFromUrl(modifiedRedirectUrl, SAMLUtils.SAML_REQUEST_PARAM_NAME));
    }

    @Test
    public void mismatchIssuerIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> ssoBindings = defaultSSOBindings();
        Map<String, String> attributeDefs = defaultAttributeDefinitions();
        String metdata = MockSAMLBuilder.createMetadataWithDefaultKey("sso_idpWRONG", ssoBindings, attributeDefs);

        Map<String, String> attributes = getDefaultAttributes();
        String responseString = createSAMLResponseWithDefaultKey(attributes, MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8));
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void mismatchedCredentialsIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> attributes = getDefaultAttributes();
        String responseString = createSAMLResponseWithDefaultKey(attributes, MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLTestUtils.readClasspathResource("sample_metadata.xml"));
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void badResponseCausesException() throws FileNotFoundException, SamlException {
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLTestUtils.readClasspathResource("sample_metadata.xml"));
        assertThrows(() -> validator.readAndValidateSAMLResponse("toast"));
        assertThrows(() -> validator.readAndValidateSAMLResponse(null));
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
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLTestUtils.readClasspathResource("sample_metadata.xml"));
        String responseString = createSAMLResponseWithDefaultKey(attributes, MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, false);
        assertThrows(() -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void supportAdditionalAttributes() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        Map<String, String> ssoBindings = defaultSSOBindings();
        Map<String, String> attributeDefs = defaultAttributeDefinitions();
        attributeDefs.put("locale", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");

        String metdata = MockSAMLBuilder.createMetadataWithDefaultKey(MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, ssoBindings, attributeDefs);

        Map<String, String> attributes = getDefaultAttributes();
        int numDefaultAttributes = attributes.size();
        attributes.put("locale", "America/Denver");
        String responseString = createSAMLResponseWithDefaultKey(attributes, MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, true);
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8));
        Response response = validator.readAndValidateSAMLResponse(responseString);


        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), numDefaultAttributes + 1);
        assertEquals(parsedAttributes, attributes);
    }


    public static Map<String, String> getDefaultAttributes() {
        return getExpectedAttributes("ue@test.com", "100");
    }

    public static Map<String, String> getExpectedAttributes(String email, String subscription) {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put(SAMLResponseValidator.EMAIL_REQUIRED_SAML_RESPONSE_ASSERTION, email);
        attributes.put(SAMLResponseValidator.SUBSCRIPTION_REQUIRED_SAML_RESPONSE_ASSERTION, subscription);
        return attributes;
    }
}
