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
package com.ericsson.nms.security.taf.test.cases;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.tools.cli.TimeoutException;
import com.ericsson.nms.security.taf.test.flows.IdentityManagementServicesTestFlow;
import com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestConstants;
import com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestScenarioUtils;
import com.ericsson.oss.testware.nodesecurity.flows.IdentityManagementServiceRestFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.inject.Inject;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestConstants.TEST_DATA_SOURCE;
import static com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestScenarioUtils.executeScenario;
import static com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestScenarioUtils.testCaseIdFilter;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_DELETE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;

public class ComAaInfoTestREST extends TafTestBase {
    private static final String READ_CONNECTION_DATA = "Verify the correct IPs and ports returned";

    @Inject
    private TestContext context;

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private IdentityManagementServiceRestFlow identityManagementServiceRestFlow;

    @Inject
    private IdentityManagementServicesTestFlow identityManagementServicesTestFlow;

    @Inject
    private identityMgmtServiceRestScenarioUtils scenarioUtils;

    @BeforeClass(groups = { "Acceptance", "RFA250" })
    public void beforeClass() {
        context.addDataSource(TEST_DATA_SOURCE, fromCsv(identityMgmtServiceRestConstants.TEST_DATA_SOURCE_CSV));
        context.addDataSource(USERS_TO_CREATE, fromCsv(identityMgmtServiceRestConstants.COMAA_INFO_USER_CSV));
        context.addDataSource(USERS_TO_DELETE, fromCsv(identityMgmtServiceRestConstants.COMAA_INFO_USER_CSV));
        context.addDataSource(AVAILABLE_USERS, fromCsv(identityMgmtServiceRestConstants.COMAA_INFO_USER_CSV));
        context.addDataSource(ROLE_TO_CREATE, fromCsv(identityMgmtServiceRestConstants.COMAA_TEST_USER_ROLE_CSV));
        context.addDataSource(ROLE_TO_DELETE, fromCsv(identityMgmtServiceRestConstants.COMAA_TEST_USER_ROLE_CSV));
        scenarioUtils.setupENMusers();
    }

    @Test(enabled = true, priority = 1, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void veryfyExpectedConnectionData() {
        final TestScenario verifyExpectedConnectionData = dataDrivenScenario(READ_CONNECTION_DATA)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("13")))
                .addFlow(identityManagementServiceRestFlow.getExpectedConnectionData())
                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("1"))
                .addFlow(identityManagementServiceRestFlow.readConnectionData())
                .addFlow(identityManagementServiceRestFlow.verifyConnectiondata())
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(verifyExpectedConnectionData);
    }

    @AfterClass(groups = { "Acceptance", "RFA250" }, alwaysRun = true)
    public void tearDown() throws TimeoutException, InterruptedException {
        scenarioUtils.tearDownScenario();
    }

}
