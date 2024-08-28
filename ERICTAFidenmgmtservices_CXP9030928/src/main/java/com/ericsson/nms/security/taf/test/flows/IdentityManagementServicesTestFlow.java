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
package com.ericsson.nms.security.taf.test.flows;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestScenarioUtils.contextFilter;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.oss.testware.nodesecurity.flows.IdentityManagementServiceRestFlow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.cifwk.taf.scenario.api.DataSourceDefinitionBuilder;
import com.ericsson.nms.security.taf.test.teststeps.IdentityManagementServicesTestSteps;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;


/**
 * Created by xadalac on 12/02/15.
 */
public class IdentityManagementServicesTestFlow {

    public static String POSIX_ATTRIBUTE_TO_DELETE = "posixAttributesToDelete";

    @Inject
    private IdentityManagementServicesTestSteps identityManagementServicesTestSteps;

    @Inject
    private LoginLogoutRestFlows loginLogoutRestFlows;



    Logger logger = LoggerFactory.getLogger(this.getClass());

    public TestStepFlow removePosixAttributes() {
        logger.info("Remove Posix Attributes");
        return flow("Remove Posix Attributes").addSubFlow(loginLogoutRestFlows.loginDefaultUser())
                .addSubFlow(flow("Remove Posix Attributes").addTestStep(annotatedMethod(identityManagementServicesTestSteps, "removePosixAttribute"))
                        .withDataSources(new DataSourceDefinitionBuilder[] { dataSource(POSIX_ATTRIBUTE_TO_DELETE) }).build())// add new source
                .addSubFlow(loginLogoutRestFlows.logout()).addSubFlow(loginLogoutRestFlows.closeTool()).build();
    }


    /**
     * subFlow used in REST TEST
     *
     * Login to ENM with functional user with proper capability and roles
     */

    public TestStepFlowBuilder loginFunctionalUser(final String predicate) {
        return flow("Login Functional user")
                .addSubFlow(loginLogoutRestFlows.login(contextFilter(predicate)));
    }
}
