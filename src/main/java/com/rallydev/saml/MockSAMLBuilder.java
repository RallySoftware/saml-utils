package com.rallydev.saml;

import com.rallydev.saml.SAMLUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDType;
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
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509IssuerSerial;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
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
import java.util.zip.GZIPOutputStream;

import static org.opensaml.xml.security.keyinfo.KeyInfoHelper.buildX509Certificate;

/**
 * Created by pairing on 2/23/18.
 */
public class MockSAMLBuilder {

    public static String createDefaultSAMLResponse() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("email", "ue@test.com");
        attributes.put("subscription", "100");
        return createSAMLResponse(attributes, "sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", false);
    }

    /**
     * Create a mock SAML Response string (base64 encoded and optionally gzipped).
     *
     * @param attributesMap   The attributes that will be included in the response Assertion
     * @param issuerName      The name of the Issuer
     * @param privateKeyFile  The location (as a URI) of the private key to use during signing; e.g. classpath:///saml.pkcs8
     * @param certificateFile The location (as a URI) of the public key certificate to use during signing; e.g. classpath:///saml.crt
     * @param gzipped         when true the xml data will be gzipped before being Base64 encoded
     * @return A SMALResponse string suitable for feeding into a {@link SAMLResponseValidator#readAndValidateSAMLResponse(String)} method
     */
    public static String createSAMLResponse(Map<String, ?> attributesMap, String issuerName, String privateKeyFile, String certificateFile, boolean gzipped) {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion = assertionBuilder.buildObject();
        AttributeStatement attributeStatement = createAttributeStatement(attributesMap);

        assertion.setID("_" + UUID.randomUUID().toString());
        assertion.setIssuer(createIssuer(issuerName));
        assertion.getAttributeStatements().add(attributeStatement);
        assertion.setSignature(createSignature(privateKeyFile, certificateFile));
        assertion.setIssueInstant(DateTime.now());

        ResponseBuilder responseBuilder = new ResponseBuilder();
        Response response = responseBuilder.buildObject();
        response.setStatus(createStatus(StatusCode.SUCCESS_URI));
        response.setID("_" + UUID.randomUUID().toString());
        response.setIssueInstant(new DateTime());
        response.getAssertions().add(assertion);
        response.setIssuer(createIssuer(issuerName));

        ResponseMarshaller marshaller = new ResponseMarshaller();
        Element element;
        try {
            element = marshaller.marshall(response);
        } catch (MarshallingException e) {
            throw new RuntimeException("error marshalling element", e);
        }

        try {
            Signer.signObject(assertion.getSignature());
        } catch (SignatureException e) {
            throw new RuntimeException("error signing assertion", e);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (gzipped) {
            try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
                XMLHelper.writeNode(element, gzip);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        } else {
            XMLHelper.writeNode(element, baos);
        }

        return Base64.encodeBytes(baos.toByteArray());
    }

    private static Issuer createIssuer(String name) {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer idpIssuer = issuerBuilder.buildObject();
        idpIssuer.setValue(name);
        return idpIssuer;
    }

    private static Status createStatus(String statusCodeStr) {
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeStr);

        StatusBuilder statusBuilder = new StatusBuilder();
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);

        return status;
    }

    private static AttributeStatement createAttributeStatement(Map<String, ?> attributes) {
        AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

        for (Map.Entry<String, ?> attributeInfo : attributes.entrySet()) {
            Attribute attribute = createAttribute(attributeInfo.getKey(), attributeInfo.getValue());
            attributeStatement.getAttributes().add(attribute);
        }
        return attributeStatement;
    }

    private static Attribute createAttribute(String name, Object value) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(name);
        XSAnyBuilder anyBuilder = new XSAnyBuilder();
        XSAny attributeValue = anyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
        attributeValue.setTextContent(String.valueOf(value));
        attribute.getAttributeValues().add(attributeValue);
        return attribute;
    }

    public static Signature createSignature(String privateKeyLocation, String publicKeyLocation) {
        try {
            SignatureBuilder builder = new SignatureBuilder();
            Signature signature = builder.buildObject();

            BasicX509Credential credential = createCredential(privateKeyLocation, publicKeyLocation);

            signature.setSigningCredential(credential);
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
            KeyInfo keyinfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            KeyInfoHelper.addCertificate(keyinfo, credential.getEntityCertificate());
            signature.setKeyInfo(keyinfo);
            return signature;
        } catch (Exception e) {
            throw new RuntimeException("error creating signature", e);
        }
    }

    public static BasicX509Credential createCredential(String privateKeyLocation, String publicKeyLocation) {
        try {
            X509Certificate publicKey = loadPublicKey(publicKeyLocation);
            PrivateKey privateKey = loadPrivateKey(privateKeyLocation);

            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(publicKey);
            credential.setPrivateKey(privateKey);
            return credential;
        } catch (CertificateException | InvalidKeySpecException e) {
            throw new RuntimeException("error loading private/public key information", e);
        }
    }

    public static PrivateKey loadPrivateKey(String locationUri) throws InvalidKeySpecException {
        try {
            byte[] buf = SAMLUtils.loadResource(locationUri);
            PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
            return KeyFactory.getInstance("RSA").generatePrivate(kspec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Unable to retrieve private key", e);
        }
    }

    public static X509Certificate loadPublicKey(String locationUri) throws CertificateException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] bytes = SAMLUtils.loadResource(locationUri);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            throw new CertificateException("Unable to retrieve public key", e);
        }
    }

    public static String createDefaultMetadata() {
        Map<String, String> ssoBindings = new HashMap<>();
        ssoBindings.put("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "https://rapid.ca.com:443/affwebservices/public/saml2sso");
        ssoBindings.put("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "https://rapid.ca.com:443/affwebservices/public/saml2sso");

        Map<String, String> attributeDefs = new HashMap<>();
        attributeDefs.put("email", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
        attributeDefs.put("subscription", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");

        return createMetadata("sso_idp", "classpath:///saml.pkcs8", "classpath:///saml.crt", ssoBindings, attributeDefs);
    }

    @SuppressWarnings("unchecked")
    public static String createMetadata(String issuer, String privateKeyLocation, String publicKeyLocation, Map<String, String> ssoBindings, Map<String, String> attributeDefinitions) {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = builder.buildObject();
        descriptor.setEntityID(issuer);

        SAMLObjectBuilder<IDPSSODescriptor> idpssoDescriptorSAMLObjectBuilder = (SAMLObjectBuilder<IDPSSODescriptor>) builderFactory.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        IDPSSODescriptor idpDescriptor = idpssoDescriptorSAMLObjectBuilder.buildObject();

        idpDescriptor.setWantAuthnRequestsSigned(false);
        idpDescriptor.addSupportedProtocol("urn:oasis:names:tc:SAML:2.0:protocol");

        idpDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.SIGNING, getServerKeyInfo(privateKeyLocation, publicKeyLocation)));

        idpDescriptor.getNameIDFormats().add(getNameIdFormat());
        ssoBindings.forEach((key, value) -> idpDescriptor.getSingleSignOnServices().add(getSingleSignOnService(key, value)));

        attributeDefinitions.forEach((name, value) -> idpDescriptor.getAttributes().add(getAttributeDefinition(name, value)));

        descriptor.getRoleDescriptors().add(idpDescriptor);

        EntityDescriptorMarshaller marshaller = new EntityDescriptorMarshaller();
        Element element;
        try {
            element = marshaller.marshall(descriptor);
        } catch (MarshallingException e) {
            throw new RuntimeException("error marshalling metadata", e);
        }

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        XMLHelper.writeNode(element, byteArrayOutputStream);

        return new String(byteArrayOutputStream.toByteArray());

    }

    private static Attribute getAttributeDefinition(String name, String nameFormat) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(name);
        attribute.setNameFormat(nameFormat);
        return attribute;
    }

    private static SingleSignOnService getSingleSignOnService(String binding, String location) {
        SingleSignOnServiceBuilder singleSignOnServiceBuilder = new SingleSignOnServiceBuilder();
        SingleSignOnService singleSignOnService = singleSignOnServiceBuilder.buildObject();
        singleSignOnService.setLocation(location);
        singleSignOnService.setBinding(binding);
        return singleSignOnService;
    }

    private static NameIDFormat getNameIdFormat() {
        SAMLObjectBuilder<NameIDFormat> builder = (SAMLObjectBuilder<NameIDFormat>) Configuration.getBuilderFactory().getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);
        NameIDFormat nameID = builder.buildObject();
        nameID.setFormat(NameIDType.UNSPECIFIED);
        return nameID;
    }

    public static KeyDescriptor getKeyDescriptor(UsageType type, KeyInfo key) {
        SAMLObjectBuilder<KeyDescriptor> builder = (SAMLObjectBuilder<KeyDescriptor>) Configuration.getBuilderFactory().getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        KeyDescriptor descriptor = builder.buildObject();
        descriptor.setUse(type);
        descriptor.setKeyInfo(key);
        return descriptor;
    }

    public static KeyInfo getServerKeyInfo(String privateKeyLocation, String publicKeyLocation) {
        try {
            KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
            KeyInfo keyinfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);

            BasicX509Credential credential = createCredential(privateKeyLocation, publicKeyLocation);

            X509Certificate x509Certificate = credential.getEntityCertificate();
            X509IssuerSerial x509IssuerSerial = KeyInfoHelper.buildX509IssuerSerial(x509Certificate.getIssuerX500Principal().getName(), x509Certificate.getSerialNumber());
            X509DataBuilder x509DataBuilder =
                    (X509DataBuilder) Configuration.getBuilderFactory().getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
            X509Data x509Data = x509DataBuilder.buildObject();
            x509Data.getX509IssuerSerials().add(x509IssuerSerial);
            x509Data.getX509Certificates().add(buildX509Certificate(x509Certificate));
            keyinfo.getX509Datas().add(x509Data);
            return keyinfo;
        } catch (Exception e) {
            return null;
        }
    }
}