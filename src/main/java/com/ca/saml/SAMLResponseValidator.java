package com.ca.saml;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Response;
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

public class SAMLResponseValidator {

    private final String ssoEntityId;
    private final Credential credential;

    public SAMLResponseValidator(String ssoEntityId, Credential credential) {
        this.ssoEntityId = ssoEntityId;
        this.credential = credential;
    }

    public SAMLObject readAndValidateSAMLResponse(String base64Parameter) throws MessageDecodingException, ValidationException {
        byte[] decode = Base64.decode(base64Parameter);
        try {
            Document messageDoc = Configuration.getParserPool().parse(new ByteArrayInputStream(decode));
            Element messageElem = messageDoc.getDocumentElement();
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(messageElem);
            if (unmarshaller == null) {
                throw new MessageDecodingException("Unable to un-marshall message, no un-marshaller registered for message element " + XMLHelper.getNodeQName(messageElem));
            }
            Response response = (Response) unmarshaller.unmarshall(messageElem);
            validate(response);
            return response;
        } catch (XMLParserException e) {
            throw new MessageDecodingException("Encountered error parsing message into its DOM representation", e);
        } catch (UnmarshallingException e) {
            throw new MessageDecodingException("Encountered error un-marshalling message from its DOM representation", e);
        }
    }

    public void validate(Response samlResponse) throws ValidationException {
        validateCredentials(samlResponse);
        validateSignatures(samlResponse);
        validateAssertion(samlResponse);
        validateDateInAssertion(samlResponse);
    }

    private void validateSignatures(SAMLObject credentials) throws ValidationException {
        if (credentials == null) {
            throw new ValidationException("Credentials was null");
        }
        boolean wasSigned = false;
        if (credentials instanceof Response) {
            Response response = (Response) credentials;
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

    private void validateDateInAssertion(Response credentials) throws ValidationException {
        Assertion assertion = credentials.getAssertions().get(0);
        Conditions conditions = assertion.getConditions();
        if (conditions == null) {
            return;
        }
        DateTime now = DateTime.now();
        if (conditions.getNotBefore() != null && now.isBefore(conditions.getNotBefore())) {
            throw new ValidationException("The assertion cannot be used before " + conditions.getNotBefore().toString());
        }
        if (conditions.getNotOnOrAfter() != null && now.isAfter(conditions.getNotOnOrAfter())) {
            throw new ValidationException("The assertion cannot be used after  " + conditions.getNotOnOrAfter().toString());
        }
    }

    private void validateAssertion(Response credentials) throws ValidationException {
        if (credentials.getAssertions().size() != 1) {
            throw new ValidationException("The response contains more than 1 assertion");
        }
        Assertion assertion = credentials.getAssertions().get(0);
        if (!assertion.getIssuer().getValue().equals(ssoEntityId)) {
            throw new ValidationException("Siteminder is the one that should be issuing the assertion");
        }
    }

    private void validateCredentials(Response credentials) throws ValidationException {
        new ResponseSchemaValidator().validate(credentials);
        if (!credentials.getIssuer().getValue().equals(ssoEntityId)) {
            throw new ValidationException("The response is not from siteminder");
        }
        String statusCode = credentials.getStatus().getStatusCode().getValue();
        if (!statusCode.equals(SAMLUtils.SAML_SUCCESS)) {
            throw new ValidationException("Invalid status code: " + statusCode);
        }
    }
}