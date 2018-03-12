package com.ca.saml;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Created by pairing on 2/23/18.
 */
public class SAMLResponseBuilder {

    public String createBase64EncodedSAMLString(String xmlResponse) {
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(xmlResponse.getBytes(StandardCharsets.UTF_8));
            os.close();
            return Base64.encodeBytes(os.toByteArray());

        } catch (Exception e) {
            return null;
        }
    }

    public String createSAMLResponse(HashMap<String, ?> attributes) {
        Issuer idpIssuer = createIssuer("sso_idp");
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion = assertionBuilder.buildObject();
        AttributeStatement attributeStatement = createAttributeStatement(attributes);

        assertion.setID("_" + UUID.randomUUID().toString());
        assertion.setIssuer(idpIssuer);
        assertion.getAttributeStatements().add(attributeStatement);
        assertion.setSignature(createSignature());
        assertion.setIssueInstant(DateTime.now());

        Response response = createResponse(assertion);

        ResponseMarshaller marshaller = new ResponseMarshaller();
        Element element = null;
        try {
            element = marshaller.marshall(response);
        } catch (MarshallingException e) {
            e.printStackTrace();
        }
        try {
            Signer.signObject(assertion.getSignature());
        } catch (SignatureException e) {
            throw new RuntimeException("error signing assertion", e);
        }

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        XMLHelper.writeNode(element, byteArrayOutputStream);

        return createBase64EncodedSAMLString(new String(byteArrayOutputStream.toByteArray()));
    }

    private Response createResponse(Assertion assertion) {
        StatusCode statusCode = getStatusCode();
        Status status = getStatus(statusCode);
        ResponseBuilder responseBuilder = new ResponseBuilder();
        Response response = responseBuilder.buildObject();
        response.setID("_" + UUID.randomUUID().toString());
        response.setIssueInstant(new DateTime());
        response.setIssuer(createIssuer("sso_idp"));
        response.getAssertions().add(assertion);
        response.setStatus(status);
        return response;
    }

    private Status getStatus(StatusCode statusCode) {
        StatusBuilder statusBuilder = new StatusBuilder();
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        return status;
    }

    private StatusCode getStatusCode() {
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        return statusCode;
    }

    private AttributeStatement createAttributeStatement(HashMap<String, ?> attributes) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

        for (Map.Entry<String, ?> attributeInfo : attributes.entrySet()) {
            Attribute attribute = createAttribute(attributeBuilder, attributeInfo);
            attributeStatement.getAttributes().add(attribute);
        }
        return attributeStatement;
    }

    private Attribute createAttribute(AttributeBuilder attributeBuilder, Map.Entry<String, ?> attributeInfo) {
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(attributeInfo.getKey());
        XSAny attributeValue = createAttributeValue();
        attributeValue.setTextContent(attributeInfo.getValue().toString());
        attribute.getAttributeValues().add(attributeValue);
        return attribute;
    }

    private XSAny createAttributeValue() {
        XSAnyBuilder anyBuilder = new XSAnyBuilder();
        return anyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
    }

    private Issuer createIssuer(String name) {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(name);
        return issuer;
    }

    private Signature createSignature() {
        try {
            SignatureBuilder builder = new SignatureBuilder();
            Signature signature = builder.buildObject();
            Credential credential = getSigningCredential();
            signature.setSigningCredential(credential);
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
            KeyInfo keyinfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Certificate x509Certificate = getPublicKey();
            KeyInfoHelper.addCertificate(keyinfo, x509Certificate);
            signature.setKeyInfo(keyinfo);
            return signature;
        } catch (Exception e) {
            return null;
        }
    }

    public Credential getSigningCredential() {
        try {
            X509Certificate publicKey = getPublicKey();
            PrivateKey privateKey = getPrivateKey();

            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(publicKey);
            credential.setPrivateKey(privateKey);

            return credential;
        } catch (Exception e) {
            return null;
        }
    }

    private PrivateKey getPrivateKey() throws InvalidKeySpecException {
        try {
            byte[] buf = SAMLUtils.readClasspathResource("saml.pkcs8");
            PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
            return KeyFactory.getInstance("RSA").generatePrivate(kspec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Unable to retirve private key", e);
        }

    }

    public X509Certificate getPublicKey() throws CertificateException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] bytes = SAMLUtils.readClasspathResource("saml.crt");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            throw new CertificateException("Unable to retrive public key", e);
        }
    }
}
