package com.rallydev.saml;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.validator.ResponseSchemaValidator;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Objects;

/**
 * A simplified SAMLResponse validation class. Only supports validating against a single IDP identity and Credential.
 */
public class SAMLResponseValidator {

    public static final String SUBSCRIPTION_REQUIRED_SAML_RESPONSE_ASSERTION = "subscription";
    public static final String EMAIL_REQUIRED_SAML_RESPONSE_ASSERTION = "email";

    private final String ssoEntityId;
    private final Credential credential;

    public SAMLResponseValidator(String ssoEntityId, Credential credential) {
        this.ssoEntityId = ssoEntityId;
        this.credential = credential;
    }

    /**
     * Decode, parse, and validate the given base64 encoded SAMLResponse. GZIP inflating will be handled automatically
     * by the underlying opensaml library.
     *
     * @param base64Parameter The string parameter to validate (typically the SAMLResponse query parameter from the servlet
     *                        request)
     * @return The parsed {@link Response} object
     * @throws MessageDecodingException for any issues decoding/inflating/parsing the SAML response data
     * @throws ValidationException      for any validation errors
     */
    public Response readAndValidateSAMLResponse(String base64Parameter) throws MessageDecodingException, ValidationException {
        return readAndValidateSAMLResponse(base64Parameter, true);
    }

    /**
     * Decode, parse, and validate the given base64 encoded SAMLResponse. GZIP inflating will be handled automatically
     * by the underlying opensaml library.
     *
     * @param base64Parameter The string parameter to validate (typically the SAMLResponse query parameter from the servlet
     *                        request)
     * @param validateDates   If true, validate date limits on SAMLResponse, else don't validate them
     * @return The parsed {@link Response} object
     * @throws MessageDecodingException for any issues decoding/inflating/parsing the SAML response data
     * @throws ValidationException      for any validation errors
     */
    public Response readAndValidateSAMLResponse(String base64Parameter, boolean validateDates) throws MessageDecodingException, ValidationException {
        Objects.requireNonNull(base64Parameter);
        byte[] decode = Base64.decode(base64Parameter);
        try {
            Document messageDoc = Configuration.getParserPool().parse(new ByteArrayInputStream(decode));
            Element messageElem = messageDoc.getDocumentElement();
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(messageElem);
            if (unmarshaller == null) {
                throw new MessageDecodingException("Unable to un-marshall message, no un-marshaller registered for message element " + XMLHelper.getNodeQName(messageElem));
            }
            Response response = (Response) unmarshaller.unmarshall(messageElem);
            validate(response, validateDates);
            return response;
        } catch (XMLParserException e) {
            throw new MessageDecodingException("Encountered error parsing message into its DOM representation", e);
        } catch (UnmarshallingException e) {
            throw new MessageDecodingException("Encountered error un-marshalling message from its DOM representation", e);
        }
    }

    /**
     * Validate the given {@link Response}. Will validate credentials, signatures, assertions, and assertion conditions.
     * This validation REQUIRES at least one signature for assertions, else the response is not considered trustworthy
     * and therefore invalid.
     *
     * @param samlResponse The SAML response to validate
     * @throws ValidationException
     */
    private void validate(Response samlResponse, boolean validateDates) throws ValidationException {
        Objects.requireNonNull(samlResponse);
        validateCredentials(samlResponse);
        validateSignatures(samlResponse);
        validateAssertion(samlResponse);
        validateDateInAssertion(samlResponse, validateDates);
        validateAuthnStatementExists(samlResponse);
        validateSubjectConfirmationData(samlResponse, validateDates);
    }

    private void validateSubjectConfirmationData(Response samlResponse, boolean validateDates) throws ValidationException {
        Assertion assertion = samlResponse.getAssertions().get(0);
        Subject subject = assertion.getSubject();
        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmations().get(0);
        SubjectConfirmationData data = subjectConfirmation.getSubjectConfirmationData();
        DateTime now = DateTime.now();

        if (validateDates && data.getNotOnOrAfter() != null && now.isAfter(data.getNotOnOrAfter())) {
            throw new ValidationException("The assertion cannot be used after  " + data.getNotOnOrAfter().toString());
        }
    }

    private void validateAuthnStatementExists(Response samlResponse) throws ValidationException{
        Assertion assertion = samlResponse.getAssertions().get(0);
        List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
        if(authnStatements.size() <= 0) {
            throw new ValidationException("there must be at least one Authn statement in SAML response");
        }

    }

    private void validateSignatures(SAMLObject samlResponse) throws ValidationException {
        if (samlResponse == null) {
            throw new ValidationException("SAML Response was null");
        }
        boolean wasSigned = false;
        if (samlResponse instanceof Response) {
            Response response = (Response) samlResponse;
            for (Assertion assertion : response.getAssertions()) {
                if (assertion.isSigned()) {
                    wasSigned = true;
                    validateSignature(assertion.getSignature());
                }
            }
        }
        if (!wasSigned) {
            throw new ValidationException("the SAML response was not signed, it can not be trusted");
        }
    }

    private void validateSignature(Signature signature) throws ValidationException {
        if (signature == null) {
            throw new ValidationException("the signature was null");
        }
        SignatureValidator signatureValidator = new SignatureValidator(credential);
        signatureValidator.validate(signature);
    }

    private void validateDateInAssertion(Response samlResponse, boolean validateDates) throws ValidationException {
        Assertion assertion = samlResponse.getAssertions().get(0);
        Conditions conditions = assertion.getConditions();
        if (conditions == null) {
            return;
        }
        DateTime now = DateTime.now();
        if (validateDates && conditions.getNotBefore() != null && now.isBefore(conditions.getNotBefore())) {
            throw new ValidationException("The assertion cannot be used before " + conditions.getNotBefore().toString());
        }
        if (validateDates && conditions.getNotOnOrAfter() != null && now.isAfter(conditions.getNotOnOrAfter())) {
            throw new ValidationException("The assertion cannot be used after  " + conditions.getNotOnOrAfter().toString());
        }
    }

    private void validateAssertion(Response samlResponse) throws ValidationException {
        if (samlResponse.getAssertions().size() != 1) {
            throw new ValidationException("The response contains more than 1 assertion");
        }
        Assertion assertion = samlResponse.getAssertions().get(0);
        if (!assertion.getIssuer().getValue().equals(ssoEntityId)) {
            throw new ValidationException(ssoEntityId + " is the one that should be issuing the assertion");
        }
    }

    private void validateCredentials(Response samlResponse) throws ValidationException {
        new ResponseSchemaValidator().validate(samlResponse);
        if (!samlResponse.getIssuer().getValue().equals(ssoEntityId)) {
            throw new ValidationException("The response is not from " + ssoEntityId);
        }
        String statusCode = samlResponse.getStatus().getStatusCode().getValue();
        if (!statusCode.equals(StatusCode.SUCCESS_URI)) {
            throw new ValidationException("Invalid status code: " + statusCode);
        }
    }
}