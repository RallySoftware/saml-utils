package com.ca.saml;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfoType;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

public class SAMLUtils {

    public static final String SAML_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (Throwable e) {
            throw new RuntimeException("error initializing opensaml", e);
        }
    }

    public static SAMLResponseValidator createSAMLResponseValidator(File metadataFile) throws FileNotFoundException, SamlException {
        MetadataProvider metadataProvider = loadSAMLMetadataFromFile(metadataFile);
        EntityDescriptor entityDescriptor;
        try {
            entityDescriptor = (EntityDescriptor) metadataProvider.getMetadata();
        } catch (MetadataProviderException ex) {
            throw new SamlException("Cannot retrieve the entity descriptor", ex);
        }
        if (entityDescriptor == null) {
            throw new SamlException("Cannot retrieve the entity descriptor");
        }

        String ssoEntityId = entityDescriptor.getEntityID();

        IDPSSODescriptor idpSsoDescriptor = entityDescriptor.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
        if (idpSsoDescriptor == null) {
            throw new SamlException("Cannot retrieve IDP SSO descriptor");
        }

        Credential credential = idpSsoDescriptor
                .getKeyDescriptors()
                .stream()
                .filter(x -> x.getUse() == UsageType.SIGNING)
                .map(KeyDescriptor::getKeyInfo)
                .filter(Objects::nonNull)
                .map(KeyInfoType::getX509Datas)
                .filter(Objects::nonNull)
                .flatMap(Collection::stream)
                .flatMap(data -> data.getX509Certificates().stream())
                .map(SAMLUtils::xmlCertToJava)
                .map(SAMLUtils::toCredential)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("no signing credential found in IDP metadata"));
        return new SAMLResponseValidator(ssoEntityId, credential);
    }

    public static MetadataProvider loadSAMLMetadataFromXMLString(String xmlMetadata) throws SamlException {
        return loadSAMLMetadata(new ByteArrayInputStream(xmlMetadata.getBytes(StandardCharsets.UTF_8)));
    }

    public static MetadataProvider loadSAMLMetadataFromFile(File metdataFile) throws FileNotFoundException, SamlException {
        return loadSAMLMetadata(new FileInputStream(metdataFile));
    }

    public static MetadataProvider loadSAMLMetadata(InputStream is) throws SamlException {
        try {
            Document messageDoc = Configuration.getParserPool().parse(is);
            DOMMetadataProvider provider = new DOMMetadataProvider(messageDoc.getDocumentElement());
            provider.initialize();
            return provider;
        } catch (MetadataProviderException | XMLParserException ex) {
            throw new SamlException("Cannot load identity provider metadata", ex);
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                // ignored
            }
        }
    }

    public static boolean validateSignatures(SAMLObject samlResponse, Credential credential) throws ValidationException {
        if (samlResponse == null || credential == null) {
            return true;
        }
        if (samlResponse instanceof Response) {
            Response response = (Response) samlResponse;
            if (response.isSigned()) {
                Signature signature = response.getSignature();
                boolean isValid = validateSignature(signature, credential);
                if (!isValid) {
                    return false;
                }
            }
            for (Assertion assertion : response.getAssertions()) {
                if (assertion.isSigned()) {
                    boolean isValid = validateSignature(assertion.getSignature(), credential);
                    if (!isValid) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    public static boolean validateSignature(Signature signature, Credential credential) throws ValidationException {
        if (signature == null || credential == null) {
            return true;
        }
        SignatureValidator validator = new SignatureValidator(credential);
        validator.validate(signature);
        return true;
    }

    public static X509Certificate xmlCertToJava(org.opensaml.xml.signature.X509Certificate xmlCertificate) {
        try {
            return KeyInfoHelper.getCertificate(xmlCertificate);
        } catch (CertificateException e) {
            throw new RuntimeException("error reading certificate from xml", e);
        }
    }

    public static Credential toCredential(X509Certificate certificate) {
        BasicX509Credential c = new BasicX509Credential();
        c.setEntityCertificate(certificate);
        c.setPublicKey(certificate.getPublicKey());
        c.setCRLs(Collections.emptyList());
        return c;
    }

    private SAMLUtils() {
    }
}
