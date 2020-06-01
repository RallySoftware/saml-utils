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
### CI Pipeline

You can run an on-demand on any git branch here:

http://microservices.ci.f4tech.com/job/saml-utils/job/0-on-demand-saml-utils/


When you merge a PR to the master branch, it will trigger the saml-utils CI pipeline to run:

http://microservices.ci.f4tech.com/job/saml-utils/job/00-saml-utils-pipeline/

The pipeline will run the tests, and if they succeed, publish the newest version of the jar to this repository:

http://repo-depot.f4tech.com/artifactory/rally-maven/com/rallydev/saml-utils-jar/


To make ALM or Zuul use the newest version of the jar, find the newest jar build number in the above repository 
and modify the saml-util references in ALM and Zuul to use it.
