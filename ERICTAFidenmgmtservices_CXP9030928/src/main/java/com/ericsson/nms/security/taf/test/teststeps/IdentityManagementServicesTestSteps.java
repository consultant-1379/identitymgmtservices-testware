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
package com.ericsson.nms.security.taf.test.teststeps;

import static com.ericsson.cifwk.taf.assertions.TafAsserts.*;

import javax.inject.Inject;
import javax.inject.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.nms.security.taf.test.models.IdentityManagementServicesResponse;
import com.ericsson.nms.security.taf.test.operators.IdentityManagementServicesOperator;
import com.ericsson.nms.security.taf.test.operators.IdentityManagementServicesRestOperator;

/**
 * Created by xadalac on 12/02/15.
 *
 * Defines test steps for management objects in Identity Management Services TAF tests
 */
public class IdentityManagementServicesTestSteps {

    private static final String OK_RESPONSE = "OK";

    final private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Inject
    private Provider<IdentityManagementServicesRestOperator> provider;

    @TestStep(id = "removePosixAttribute")
    public void removePosixAttribute(@Input("userName") final String userName,
                                     @Input("posixAttributeGroupName") final String posixAttributeGroupName) {

        logger.info("Remove Posix Attribute");
        final IdentityManagementServicesOperator operator = provider.get();
        final IdentityManagementServicesResponse result = operator.removePosixAttribute(userName, posixAttributeGroupName);
        assertThat("Posix Attribute has not been removed", result.getResult().equals(OK_RESPONSE));

    }
}