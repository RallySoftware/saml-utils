package com.rallydev.saml;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    public static String getResourceFileContentsAsString(String resourceFileName) throws IOException {
        Class clazz = SAMLResponseValidator.class;
        InputStream inputStream = clazz.getResourceAsStream(resourceFileName);
        return readFromInputStream(inputStream);
    }

    private static String readFromInputStream(InputStream inputStream)
            throws IOException {
        StringBuilder resultStringBuilder = new StringBuilder();
        try (BufferedReader br
                     = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = br.readLine()) != null) {
                resultStringBuilder.append(line).append("\n");
            }
        }
        return resultStringBuilder.toString();
    }

    public static String getParamFromUrl(String urlString, String paramName) {
        Pattern regexPattern = Pattern.compile("(&?)" + paramName + "=[^&]*");
        Matcher matcher = regexPattern.matcher(urlString);
        if (matcher.find()) {
            return matcher.group(0);
        }
        return null;
    }

    public static byte[] readClasspathResource(String resource) {
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
    }

}
