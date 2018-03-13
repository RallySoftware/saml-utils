# saml-utils
Utilities for SSO using SAML - used by ALM and Zuul

This repo houses the common utilies used by ALM and Zuul for SAML response validation.

#### Usage
Create the validator from the IDP partner metadata exported by SiteMinder:
```java
SAMLResponseValidator validator = SAMLUtils.createSAMLResponseValidator(new File("./idp_metadata.xml"));
```

Validate a SAMLResponse:
```java
String samlResponse = request.getParameter("SAMLResponse");
Response response = validator.readAndValidateSAMLResponse(samlResponse);
```

And pull the attributes from the response:
```java
Map<String, String> parsedAttributes = SAMLUtils.getAttributes(response);
// contains, for example:
// 'email' => 'ue@ca.com'
// 'subscription => '100'
```
