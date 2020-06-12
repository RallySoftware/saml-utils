package com.rallydev.saml;

import org.testng.Assert;
import org.testng.annotations.Test;

public class AuthNRequestBuilderTest extends Assert {

    private static final String DEV_ALM_UNSTRIPPED_SAML_RESPONSE_ACS_URL = "http://localhost:7001/slm/j_saml_security_check";

    static {
        SAMLUtils.init();
    }

    @Test
    public void buildAuthnRequestAndConvertToParam() throws SamlException
    {
        String assertionConsumerServiceUrl = DEV_ALM_UNSTRIPPED_SAML_RESPONSE_ACS_URL;
        String issuerId = SAMLUtils.SP_ENTITY_ID_ALM;
        String samlRequestParam = SAMLUtils.generateSAMLRequestParameterValue(assertionConsumerServiceUrl, issuerId);
        assertTrue(samlRequestParam == null);
        assertTrue(!samlRequestParam.isEmpty());
        //need to add something that will compare with master
    }

}
