/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.nms.security.taf.test.teststeps;

import javax.inject.Inject;
import javax.inject.Provider;

import org.unitils.reflectionassert.ReflectionAssert;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.nms.security.taf.test.operators.ComAaOperator;
import com.ericsson.nms.security.taf.test.operators.ComAaOperatorImpl;
import com.ericsson.oss.itpf.security.identitymgmtservices.comaa.ConnectionData;

public class ComAAInfoTestSteps extends TafTestBase {

    public static final String SHOULD_RETURN_CORRECT_CONNECTION_DATA = "shouldReturnCorrectConnectionData";

    @Inject
    private Provider<ComAaOperatorImpl> provider;

    @TestStep(id = SHOULD_RETURN_CORRECT_CONNECTION_DATA)
    public void shouldReturnCorrectConnectionData() {
        final ComAaOperator comAAOperator = provider.get();
        final ConnectionData expectedConnectionData = comAAOperator.getExpectedConnectionData();
        final ConnectionData connectionData = comAAOperator.getConnectionData();
        ReflectionAssert.assertReflectionEquals(expectedConnectionData, connectionData);
    }
}
