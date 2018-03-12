package com.ca.saml;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509IssuerSerial;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;

import static org.opensaml.xml.security.keyinfo.KeyInfoHelper.buildX509Certificate;


public class SAMLMetadataBuilder {

    public String createMetadata() {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = builder.buildObject();
        descriptor.setEntityID("sso_idp");


        SAMLObjectBuilder<IDPSSODescriptor> idpssoDescriptorSAMLObjectBuilder = (SAMLObjectBuilder<IDPSSODescriptor>) builderFactory.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        IDPSSODescriptor idpDescriptor = idpssoDescriptorSAMLObjectBuilder.buildObject();

        idpDescriptor.setWantAuthnRequestsSigned(false);
        idpDescriptor.addSupportedProtocol("urn:oasis:names:tc:SAML:2.0:protocol");

        idpDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.SIGNING, getServerKeyInfo()));

        idpDescriptor.getNameIDFormats().add(getNameIdFormat());
        idpDescriptor.getSingleSignOnServices().add(getSingleSignOnService("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "https://rapid.ca.com:443/affwebservices/public/saml2sso"));
        idpDescriptor.getSingleSignOnServices().add(getSingleSignOnService("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "https://rapid.ca.com:443/affwebservices/public/saml2sso"));

        idpDescriptor.getAttributes().add(getAttribute("email", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"));
        idpDescriptor.getAttributes().add(getAttribute("subscription", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"));

        descriptor.getRoleDescriptors().add(idpDescriptor);

        EntityDescriptorMarshaller marshaller = new EntityDescriptorMarshaller();
        Element element = null;
        try {
            element = marshaller.marshall(descriptor);
        } catch (MarshallingException e) {
            e.printStackTrace();
        }

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        XMLHelper.writeNode(element, byteArrayOutputStream);

        return new String(byteArrayOutputStream.toByteArray());

    }

    private Attribute getAttribute(String name, String nameFormat) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(name);
        attribute.setNameFormat(nameFormat);
        return attribute;
    }

    private SingleSignOnService getSingleSignOnService(String binding, String location) {
        SingleSignOnServiceBuilder singleSignOnServiceBuilder = new SingleSignOnServiceBuilder();
        SingleSignOnService singleSignOnService = singleSignOnServiceBuilder.buildObject();
        singleSignOnService.setLocation(location);
        singleSignOnService.setBinding(binding);
        return singleSignOnService;
    }

    private NameIDFormat getNameIdFormat() {
        SAMLObjectBuilder<NameIDFormat> builder = (SAMLObjectBuilder<NameIDFormat>) Configuration.getBuilderFactory().getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);
        NameIDFormat nameID = builder.buildObject();
        nameID.setFormat(NameIDType.UNSPECIFIED);
        return nameID;
    }

    public KeyDescriptor getKeyDescriptor(UsageType type, KeyInfo key) {
        SAMLObjectBuilder<KeyDescriptor> builder = (SAMLObjectBuilder<KeyDescriptor>) Configuration.getBuilderFactory().getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        KeyDescriptor descriptor = builder.buildObject();
        descriptor.setUse(type);
        descriptor.setKeyInfo(key);
        return descriptor;
    }

    public KeyInfo getServerKeyInfo() {
        try {
            KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
            KeyInfo keyinfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Certificate x509Certificate = ((X509Credential) (new SAMLResponseBuilder().getSigningCredential())).getEntityCertificate();
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
