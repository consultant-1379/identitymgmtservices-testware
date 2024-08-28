/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.nms.security.taf.test.operators;

import javax.inject.Inject;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.tools.http.HttpResponse;
import com.ericsson.nms.security.taf.test.models.IdentityManagementServicesResponse;
import com.ericsson.oss.testware.security.authentication.tool.TafToolProvider;

/**
 * Created by xadalac on 12/02/15.
 *
 * This class provides sending REST requests for Identity Management Services.
 */
public class IdentityManagementServicesRestOperator implements IdentityManagementServicesOperator {

    private static final String IDMSERVICE_URI = "/idmservice/people/";
    private static final String POSIXATTRIBUTES_URI = "/posixattributes?groupname=";
    private static final String OK_RESPONSE = "OK";

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Inject
    TafToolProvider tafToolProvider;

    @Override
    public IdentityManagementServicesResponse removePosixAttribute(final String userName, final String posixAttributeGroupName) {
        logger.info("Is logged: {} \nCreate http request for command \"removePosixAttribute\" for Posix Attribute: {}",
                !(tafToolProvider.getHttpTool().get("/#launcher").getBody().contains("IDToken1")), posixAttributeGroupName);

        final String uri = new StringBuilder(IDMSERVICE_URI).append(userName).append(POSIXATTRIBUTES_URI).append(posixAttributeGroupName).toString();

        logger.info(uri);

        final HttpResponse response = tafToolProvider.getHttpTool().request().delete(uri);
        final String responseCode = response.getResponseCode().toString();

        logger.info("Response code: {}\nBody: {}", responseCode, response.getBody());

        final IdentityManagementServicesResponse<String> identityManagementServicesResponse = new IdentityManagementServicesResponse<>();
        if (responseCode.equals(OK_RESPONSE)) {
            identityManagementServicesResponse.setResult(responseCode);
        } else {
            final JSONObject jsonResponse = new JSONObject(response.getBody());
            identityManagementServicesResponse.setResult(jsonResponse.getString("code"));
        }
        return identityManagementServicesResponse;
    }

}
