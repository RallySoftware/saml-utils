package com.rallydev.saml;

import java.util.HashMap;
import java.util.Map;

public class SAMLTestUtils {

    public static Map<String, String> defaultSSOBindings() {
        Map<String, String> ssoBindings = new HashMap<>();
        ssoBindings.put("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "https://rapid.ca.com:443/affwebservices/public/saml2sso");
        ssoBindings.put("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "https://rapid.ca.com:443/affwebservices/public/saml2sso");
        return ssoBindings;
    }

    public static Map<String, String> defaultAttributeDefinitions() {
        Map<String, String> attributeDefs = new HashMap<>();
        attributeDefs.put("email", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
        attributeDefs.put("subscription", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
        return attributeDefs;
    }
}
