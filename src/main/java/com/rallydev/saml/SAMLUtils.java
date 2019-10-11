package com.rallydev.saml;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfoType;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
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
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * Static SAML utilities.
 */
public class SAMLUtils {

    public static final String SP_ENTITY_ID_ALM = "alm_sp";
    public static final String SP_ENTITY_ID_ZUUL = "sp_zuul";

    public static final String SAML_REQUEST_PARAM_NAME = "SAMLRequest";

    public static final String DEV_ZUUL_SAML_RESPONSE_ACS_URL = "http://localhost:3000/login/sso";

    public static final String DEV_ALM_STRIPPED_OPEN_TOKEN_ACS_URL = "http://localhost:7001/j_sso_security_check";

    public static final String DEV_ALM_STRIPPED_SAML_RESPONSE_ACS_URL = "http://localhost:7001/j_saml_security_check";
    public static final String DEV_ALM_UNSTRIPPED_SAML_RESPONSE_ACS_URL = "http://localhost:7001/slm/j_saml_security_check";

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

    /**
     * Create a new {@link SAMLResponseValidator} from the given IDP metadata XML file.
     *
     * @param metadataFile The IDP exported XML metadata file
     * @return A new SAMLResponseValidator that will use the entity ID and credential found in the metadata to validate
     * responses.
     * @throws IOException   On any file read error
     * @throws SamlException On any error parsing/validating the metadata
     */
    public static SAMLResponseValidator createSAMLResponseValidator(File metadataFile, String spEntityId, String recepient) throws IOException, SamlException {
        return createSAMLResponseValidator(loadSAMLMetadataFromFile(metadataFile), spEntityId, recepient);
    }

    /**
     * Create a new {@link SAMLResponseValidator} from the given IDP metadata XML bytes.
     *
     * @param metadataXmlBytes The IDP metadata
     * @return A new SAMLResponseValidator that will use the entity ID and credential found in the metadata to validate
     * responses.
     * @throws SamlException On any error parsing/validating the metadata
     */
    public static SAMLResponseValidator createSAMLResponseValidator(byte[] metadataXmlBytes, String spEntityId, String recepient) throws SamlException {
        MetadataProvider metadataProvider = loadSAMLMetadata(new ByteArrayInputStream(metadataXmlBytes));
        return createSAMLResponseValidator(metadataProvider, spEntityId, recepient);
    }

    private static SAMLResponseValidator createSAMLResponseValidator(MetadataProvider metadataProvider, String spEntityId, String recepient) throws SamlException {
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
        return new SAMLResponseValidator(ssoEntityId, credential, recepient, spEntityId);
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

    public static byte[] loadResource(String locationUri) {
        System.out.println(String.format("loadResource: locationUri: %s", locationUri));
        try {
            try {
                URI uri = URI.create(locationUri);
                String scheme = uri.getScheme();
                if (Objects.equals(scheme, "classpath")) {
                    return readClasspathResource(uri.getPath());
                } else {
                    return Files.readAllBytes(new File(uri.getPath()).toPath());
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        } catch (Throwable t) {
            t.printStackTrace(System.out);
            throw t;
        }

    }

    public static byte[] readClasspathResource(String resource) {
        System.out.println(String.format("readClasspathResource: resource: %s", resource));
        try {
            while (resource.startsWith("/")) {
                resource = resource.substring(1);
            }
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
        } catch (Throwable t) {
            t.printStackTrace(System.out);
            throw t;
        }
    }

    /**
     * Get all attributes from the SAML Response. This will iterate through all assertions and attributes statements
     * to pull the names and values of the attributes. WARNING: If there are duplicate attribute names, only the last
     * one found will be returned.
     *
     * @param response The SAML response to get attributes from
     * @return An immutable map of attribute name:value pairs
     */
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

    public static String modifyRedirectUrlForDevTestSSOFederationServer(String redirectUrl, String assertionConsumerServiceURL, String spEntityId, boolean useDevTestSSOFederationServer) {
        if (!useDevTestSSOFederationServer) {
            return redirectUrl;
        }

        try {
            init();
            String samlRequestParam = SAMLUtils.generateSAMLRequestParameterValue(assertionConsumerServiceURL, spEntityId);
            redirectUrl = addParamToUrl(redirectUrl, SAML_REQUEST_PARAM_NAME + "=" + samlRequestParam);
        } catch (Exception ex) {
            ex.printStackTrace(System.out);
            // if failed to modify redirectUrl, just return unmodified url
        }

        return redirectUrl;
    }

    /**
     * Add param to URL, respecting '?' & '&' rules
     * @param existingUrl
     * @param queryParam Remember to encode the right hand side of the '=' in the param, if necessary!  (RequestUtils.urlEncode)
     */
    public static String addParamToUrl(String existingUrl, String queryParam) {
        if (queryParam == null || queryParam.length() == 0) {
            return existingUrl;
        }
        String separator = existingUrl.contains("?") ? "&" : "?";
        return existingUrl + separator + queryParam;
    }

    // This method borrowed from
    // https://github.com/sunieldalal/loginapp/blob/master/src/main/java/com/slabs/login/service/login/LoginServiceImpl.java

    public static String generateSAMLRequestParameterValue(String assertionConsumerServiceUrl, String issuerId) throws SamlException {
        try {
            AuthnRequest authRequest = AuthNRequestBuilder.buildAuthenticationRequest(assertionConsumerServiceUrl, issuerId);
            Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(authRequest);
            org.w3c.dom.Element authDOM = marshaller.marshall(authRequest);
            StringWriter rspWrt = new StringWriter();
            XMLHelper.writeNode(authDOM, rspWrt);
            String messageXML = rspWrt.toString();

            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                 DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater)) {
                deflaterOutputStream.write(messageXML.getBytes());
                // we must close  deflaterOutputStream here else byteArrayOutputStream.toByteArray() returns empty array
                deflaterOutputStream.close();
                String samlRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
                return URLEncoder.encode(samlRequest, "UTF-8");
            }
        }
        catch (Exception ex)
        {
            throw new SamlException("Failed to generate SAML Request", ex);
        }
    }
}
