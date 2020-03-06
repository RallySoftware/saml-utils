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
        String audience = MockSAMLBuilder.DEFAULT_AUDIENCE;

        String defaultMetadata = MockSAMLBuilder.createDefaultMetadata();
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(defaultMetadata.getBytes(StandardCharsets.UTF_8), audience);

        String responseString = MockSAMLBuilder.createDefaultSAMLResponse();
        Response response = validator.readAndValidateSAMLResponse(responseString);

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        Map<String, String> expectedAttributes = getDefaultAttributes();
        expectedAttributes.put(SAMLResponseValidator.AUDIENCE_REQUIRED_SAML_RESPONSE_CONDITION, audience);

        assertEquals(parsedAttributes.size(), expectedAttributes.size());
        assertEquals(parsedAttributes, expectedAttributes);
    }

    @Test(expectedExceptions = ValidationException.class, expectedExceptionsMessageRegExp = "the SAML response does not have the expected audience: expected=bogusAudience  actual=https://rally1.rallydev.com")
    public void throwsUnexpectedAudienceException() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        String audienceInResponse = "bogusAudience";
        String expectedAudience = MockSAMLBuilder.DEFAULT_AUDIENCE;

        String defaultMetadata = MockSAMLBuilder.createDefaultMetadata();
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(defaultMetadata.getBytes(StandardCharsets.UTF_8), audienceInResponse);

        String responseString = MockSAMLBuilder.createDefaultSAMLResponse();
        Response response = validator.readAndValidateSAMLResponse(responseString);

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        Map<String, String> expectedAttributes = getDefaultAttributes();
        expectedAttributes.put(SAMLResponseValidator.AUDIENCE_REQUIRED_SAML_RESPONSE_CONDITION, expectedAudience);

        assertEquals(parsedAttributes.size(), expectedAttributes.size());
        assertEquals(parsedAttributes, expectedAttributes);
    }

    @Test
    public void validateMockIdpSamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        // Mujina IDP
        validateSAMLResponse(
                "user@mockidpsub.com",
                "103",
                "http://localhost",
                "/mock-idp-metadata.xml",
                "/mock-idp-samlResponse.txt");
    }

    @Test
    public void validate_Okta_exknyz5bdks93pPNy0h7_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        // OKTA_PREVIEW_LOCALHOST_SSO_METADATA_LOCATION
        validateSAMLResponse(
                "ssouser1@test.com",
                "170904",
                "http://localhost",
                "/www.okta.com-exknyz5bdks93pPNy0h7-metadata.xml",
                "/www.okta.com-exknyz5bdks93pPNy0h7-samlResponse.txt"
        );
    }

    @Test
    public void validate_Okta_exko9ji5yhMifwM6G0h7_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        // OKTA_PREVIEW_TESTN_SSO_METADATA_LOCATION
        validateSAMLResponse(
                "ssouser1@test.com",
                "170904",
                "https://oktatest100.testn.f4tech.com",
                "/www.okta.com-exko9ji5yhMifwM6G0h7-metadata.xml",
                "/www.okta.com-exko9ji5yhMifwM6G0h7-samlResponse.txt");
    }

    @Test
    public void validate_Okta_exkoya2eyoW7S7OW80h7_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        // OKTA_PREVIEW_RALLY_PROD_SSO_METADATA_LOCATION
        validateSAMLResponse(
                "ssouser1@test.com",
                "170904",
                "https://rally1.rallydev.com",
                "/www.okta.com-exkoya2eyoW7S7OW80h7-metadata.xml",
                "/www.okta.com-exkoya2eyoW7S7OW80h7-samlResponse.txt");
    }

    @Test
    public void validate_Okta_exk1gdbaindeR1Jrj1d8_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        // OKTA_PROD_RALLY_PROD_SSO_METADATA_LOCATION
        validateSAMLResponse(
                "prodssouser1@test.com",
                "170904",
                "https://rally1.rallydev.com",
                "/www.okta.com-exk1gdbaindeR1Jrj1d8-metadata.xml",
                "/www.okta.com-exk1gdbaindeR1Jrj1d8-samlResponse.txt");
    }

    @Test
    public void validate_Okta_exk1gf4q36mwg5sJO1d8_SamlResponse() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        // OKTA_PROD_EU_RALLY_PROD_EU_SSO_METADATA_LOCATION
        validateSAMLResponse(
                "prodssousereu1@test.com",
                "101165",
                "https://eu1.rallydev.com",
                "/www.okta.com-exk1gf4q36mwg5sJO1d8-metadata.xml",
                "/www.okta.com-exk1gf4q36mwg5sJO1d8-samlResponse.txt");
    }


    private List<String> getRequiredAssertionKeys() {
        return Arrays.asList(
                SAMLResponseValidator.SUBSCRIPTION_REQUIRED_SAML_RESPONSE_ASSERTION,
                SAMLResponseValidator.EMAIL_OPTIONAL_SAML_RESPONSE_ASSERTION);
    }

    private void validateSAMLResponse(
            String username,
            String subscription,
            String audience,
            String metadataPath,
            String samlResponsePath) throws IOException, SamlException, MessageDecodingException, ValidationException {
        String idpMetadata = SAMLTestUtils.getResourceFileContentsAsString(metadataPath);
        String responseString = SAMLTestUtils.getResourceFileContentsAsString(samlResponsePath);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(idpMetadata.getBytes(StandardCharsets.UTF_8), audience);
        Response response = validator.readAndValidateSAMLResponse(responseString, false);

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        Map<String, String> requiredAttributes = parsedAttributes.
                entrySet().stream()
                .filter(x -> getRequiredAssertionKeys().contains(x.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        assertEquals(requiredAttributes.size(), getRequiredAssertionKeys().size());

        Map<String, String> expectedAttributes = getExpectedAttributes(username, subscription, username);
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

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8), MockSAMLBuilder.DEFAULT_AUDIENCE);
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void mismatchedCredentialsIsNotValid() throws FileNotFoundException, SamlException {
        Map<String, String> attributes = getDefaultAttributes();
        String responseString = createSAMLResponseWithDefaultKey(attributes, MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, false);

        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLTestUtils.readClasspathResource("sample_metadata.xml"), MockSAMLBuilder.DEFAULT_AUDIENCE);
        assertThrows(ValidationException.class, () -> validator.readAndValidateSAMLResponse(responseString));
    }

    @Test
    public void badResponseCausesException() throws FileNotFoundException, SamlException {
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLTestUtils.readClasspathResource("sample_metadata.xml"), MockSAMLBuilder.DEFAULT_AUDIENCE);
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

    private void assertThrowsErrorWithAttributes(String key, Object value) throws SamlException{
        Map attributes = getDefaultAttributes();
        attributes.put(key, value);
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(SAMLTestUtils.readClasspathResource("sample_metadata.xml"), MockSAMLBuilder.DEFAULT_AUDIENCE);
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
        attributes.put("locale", "America/Denver");
        attributes.put(SAMLResponseValidator.AUDIENCE_REQUIRED_SAML_RESPONSE_CONDITION, MockSAMLBuilder.DEFAULT_AUDIENCE);
        int numAttributes = attributes.size();
        String responseString = createSAMLResponseWithDefaultKey(attributes, MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, true);
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8), MockSAMLBuilder.DEFAULT_AUDIENCE);
        Response response = validator.readAndValidateSAMLResponse(responseString);


        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);
        assertEquals(parsedAttributes.size(), numAttributes);
        assertEquals(parsedAttributes, attributes);
    }

    @Test
    public void supportMissingEmailAttribute() throws IOException, SamlException, ValidationException, MessageDecodingException, TransformerException {
        Map<String, String> ssoBindings = defaultSSOBindings();
        Map<String, String> attributeDefs = defaultAttributeDefinitions();
        attributeDefs.put("locale", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");

        String metdata = MockSAMLBuilder.createMetadataWithDefaultKey(MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, ssoBindings, attributeDefs);

        Map<String, String> attributes = getDefaultAttributes();
        attributes.put("locale", "America/Denver");
        attributes.put(SAMLResponseValidator.AUDIENCE_REQUIRED_SAML_RESPONSE_CONDITION, MockSAMLBuilder.DEFAULT_AUDIENCE);

        // Remove the 'email' assertion from the attributes passed to createSAMLResponseWithDefaultKey(),
        // so the SAML Response it generates will not have an 'email' assertion in it.
        String emailValue = attributes.remove(SAMLResponseValidator.EMAIL_OPTIONAL_SAML_RESPONSE_ASSERTION);

        String responseString = createSAMLResponseWithDefaultKey(attributes, MockSAMLBuilder.SAMPLE_IDP_ENTITY_ID, true);
        SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(metdata.getBytes(StandardCharsets.UTF_8), MockSAMLBuilder.DEFAULT_AUDIENCE);
        Response response = validator.readAndValidateSAMLResponse(responseString);

        Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
        System.out.println(parsedAttributes);

        // Even though there is no 'email' assertion in the SAML response,
        // getAttributes()  returns the value of the SAML Subject in the SAML response as the the value of the 'eamil' assertion
        attributes.put(SAMLResponseValidator.EMAIL_OPTIONAL_SAML_RESPONSE_ASSERTION, emailValue);

        assertEquals(parsedAttributes.size(), attributes.size());
        assertEquals(parsedAttributes, attributes);
    }

    private static Map<String, String> getDefaultAttributes() {
        return getExpectedAttributes(MockSAMLBuilder.DEFAULT_EMAIL, MockSAMLBuilder.DEFAULT_SUBSCRIPTION, MockSAMLBuilder.DEFAULT_SUBJECT);
    }

    private static Map<String, String> getExpectedAttributes(String email, String subscription, String subject) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put(SAMLResponseValidator.EMAIL_OPTIONAL_SAML_RESPONSE_ASSERTION, email);
        attributes.put(SAMLResponseValidator.SUBSCRIPTION_REQUIRED_SAML_RESPONSE_ASSERTION, subscription);
        return attributes;
    }
}
