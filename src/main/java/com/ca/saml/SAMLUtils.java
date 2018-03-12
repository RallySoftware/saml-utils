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
import org.opensaml.xml.XMLObject;
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

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

public class SAMLUtils {

    public static final String SAML_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

    private static final AtomicBoolean initialized = new AtomicBoolean(false);

    public static void init() {
        if (initialized.compareAndSet(false, true)) {
            try {
                DefaultBootstrap.bootstrap();
            } catch (Throwable e) {
                throw new RuntimeException("error initializing opensaml", e);
            }
        }
    }

    public static SAMLResponseValidator createSAMLResponseValidator(File metadataFile) throws IOException, SamlException {
        return createSAMLResponseValidator(Files.readAllBytes(metadataFile.toPath()));
    }

    public static SAMLResponseValidator createSAMLResponseValidator(byte[] metadataXmlBytes) throws FileNotFoundException, SamlException {
        MetadataProvider metadataProvider = loadSAMLMetadata(new ByteArrayInputStream(metadataXmlBytes));
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

        Credential credential = getFirstCredential(idpSsoDescriptor)
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

    public static Optional<Credential> getFirstCredential(IDPSSODescriptor descriptor) {
        return descriptor.getKeyDescriptors()
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
                .findFirst();
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

    public static byte[] readClasspathResource(String resource) {
        try (InputStream is = SAMLUtils.class.getClassLoader().getResourceAsStream(resource)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int read;
            while ((read = is.read(buf)) >= 0) {
                baos.write(buf, 0, read);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static Map<String, String> getAttributes(Response response) {
        Map<String, String> map = new HashMap<>();
        response.getAssertions().stream()
                .flatMap(assertion -> assertion.getAttributeStatements().stream())
                .flatMap(attributeStatement -> attributeStatement.getAttributes().stream())
                .forEach(attribute -> {
                    String name = attribute.getName();
                    String content = attribute.getAttributeValues().get(0).getDOM().getTextContent();
                    map.put(name, content);
                });
        return Collections.unmodifiableMap(map);
    }

    public static String toString(XMLObject object) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(new DOMSource(object.getDOM()), new StreamResult(new OutputStreamWriter(baos, "UTF-8")));
            return new String(baos.toByteArray(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("error converting to string", e);
        }
    }

    private SAMLUtils() {
    }
}
