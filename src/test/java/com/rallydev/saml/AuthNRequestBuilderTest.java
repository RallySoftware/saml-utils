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
        String assertionConsumerServiceUrl = SAMLUtils.DEV_ALM_UNSTRIPPED_SAML_RESPONSE_ACS_URL;
        String issuerId = SAMLUtils.SP_ENTITY_ID_ALM;
        String samlRequestParam = SAMLUtils.generateSAMLRequestParameterValue(assertionConsumerServiceUrl, issuerId);
        assertTrue(samlRequestParam != null);
        assertTrue(!samlRequestParam.isEmpty());
    }

}
