package com.rallydev.saml;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;

import java.util.UUID;

import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;


// This class borrowed from
// https://github.com/sunieldalal/loginapp/blob/master/src/main/java/com/slabs/login/service/login/AuthNRequestBuilder.java

public class AuthNRequestBuilder {

    private static final String SAML2_NAME_ID_POLICY = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    private static final String SAML2_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SAML2_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    private static final String SAML2_PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    private static final String SAML2_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

    /**
     * Generate an authentication request.
     *
     * @return AuthnRequest Object
     */
    public static AuthnRequest buildAuthenticationRequest(String assertionConsumerServiceUrl, String issuerId) {

        //Generate ID
        DateTime issueInstant = new DateTime();
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest = authRequestBuilder.buildObject(SAML2_PROTOCOL, "AuthnRequest", "samlp");
        authRequest.setForceAuthn(Boolean.FALSE);
        authRequest.setIsPassive(Boolean.FALSE);
        authRequest.setIssueInstant(issueInstant);
        authRequest.setProtocolBinding(SAML2_POST_BINDING);
        authRequest.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
        authRequest.setIssuer(buildIssuer( issuerId));
        authRequest.setNameIDPolicy(buildNameIDPolicy());
        authRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
        authRequest.setID(UUID.randomUUID().toString());
        authRequest.setVersion(SAMLVersion.VERSION_20);

        return authRequest;
    }

    /**
     * Build the issuer object
     *
     * @return Issuer object
     */
    private static Issuer buildIssuer(String issuerId) {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerId);
        return issuer;
    }

    /**
     * Build the NameIDPolicy object
     *
     * @return NameIDPolicy object
     */
    private static NameIDPolicy buildNameIDPolicy() {
        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setFormat(SAML2_NAME_ID_POLICY);
        nameIDPolicy.setAllowCreate(Boolean.TRUE);
        return nameIDPolicy;
    }

    /**
     * Build the RequestedAuthnContext object
     *
     * @return RequestedAuthnContext object
     */
    private static RequestedAuthnContext buildRequestedAuthnContext() {

        //Create AuthnContextClassRef
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef =
                authnContextClassRefBuilder.buildObject(SAML2_ASSERTION, "AuthnContextClassRef", "saml");
        authnContextClassRef.setAuthnContextClassRef(SAML2_PASSWORD_PROTECTED_TRANSPORT);

        //Create RequestedAuthnContext
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
        RequestedAuthnContext requestedAuthnContext =
                requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        return requestedAuthnContext;
    }
}