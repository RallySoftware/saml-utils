package com.rallydev.saml;

import org.testng.Assert;
import org.testng.annotations.Test;

public class AuthNRequestBuilderTest extends Assert {

    static {
        SAMLUtils.init();
    }

    @Test
    public void buildAuthnRequestAndConvertToParam() throws SamlException
    {
        String assertionConsumerServiceUrl = "http://localhost:7001/slm/j_saml_security_check";
        String issuerId = "alm_sp";
        String samlRequestParam = SAMLUtils.generateSAMLRequestParameterValue(assertionConsumerServiceUrl, issuerId);
        assertTrue(samlRequestParam != null);
        assertTrue(!samlRequestParam.isEmpty());
    }

}
