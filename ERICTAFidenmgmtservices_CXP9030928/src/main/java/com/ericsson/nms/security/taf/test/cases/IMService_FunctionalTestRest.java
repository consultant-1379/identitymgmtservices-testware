/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2022
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import javax.inject.Inject;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestConstants.TEST_DATA_SOURCE;
import static com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestScenarioUtils.executeScenario;
import static com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestScenarioUtils.testCaseIdFilter;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_DELETE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;
import static com.ericsson.oss.testware.nodesecurity.steps.IdentityManagementServiceRestTestStep.CHECK_COM_USER_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.IdentityManagementServiceRestTestStep.CHECK_M2M_USER_EXIST_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.IdentityManagementServiceRestTestStep.CLEAN_UP_M2M_USER_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.IdentityManagementServiceRestTestStep.CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.IdentityManagementServiceRestTestStep.CREATE_M2M_USER_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.IdentityManagementServiceRestTestStep.DELETE_M2M_USER_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.IdentityManagementServiceRestTestStep.GET_M2M_USER_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.IdentityManagementServiceRestTestStep.GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE;
import static com.ericsson.nms.security.taf.test.utility.identityMgmtServiceRestScenarioUtils.contextFilter;

public class IMService_FunctionalTestRest extends TafTestBase {

    private static final String DELETE_M2M_USER = "Delete m2m users";
    private static final String CREATE_M2M_USER ="Create m2m users";
    private static final String CHECK_M2M_USER = "Check m2m user existence";
    private static final String GET_M2M_USER = "Get m2m user";
    private static final String UPADATE_M2M_USER_PASSWORD = "Update m2m user password";
    private static final String GET_M2M_USER_PASSWORD = "Get m2m user password";
    private static final String CREATE_PROXY_ACCOUNT = "Create aProxy Agent";
    private static final String DELETE_PROXY_ACCOUNT = "Delete Proxy Agent";
    private static final String CHECK_COM_USER = "Check ENM user has ComRole assigned";
    private static final String USER_CANNOT_ACCESS_TO_API = "Verify ENM User cannot access to End-Point REST API without proper 'Custom Role' assigned";


    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private TestContext context;

    @Inject
    private IdentityManagementServiceRestFlow identityManagementServiceRestFlow;


    @Inject
    private IdentityManagementServicesTestFlow identityManagementServicesTestFlow;

    @Inject
    private identityMgmtServiceRestScenarioUtils scenarioUtils;



    /*
    * Set up Scenario
    * Create ENM users and clean Up any m2m users that exist
    */

    @BeforeClass(groups = { "Acceptance", "RFA250" })
    public void beforeClass() {
        context.addDataSource(TEST_DATA_SOURCE, fromCsv(identityMgmtServiceRestConstants.TEST_DATA_SOURCE_CSV));
        context.addDataSource(USERS_TO_CREATE, fromCsv(identityMgmtServiceRestConstants.IDENTITY_MGMT_SERVICE_USER_CSV));
        context.addDataSource(USERS_TO_DELETE, fromCsv(identityMgmtServiceRestConstants.IDENTITY_MGMT_SERVICE_USER_CSV));
        context.addDataSource(AVAILABLE_USERS, fromCsv(identityMgmtServiceRestConstants.IDENTITY_MGMT_SERVICE_USER_CSV));
        context.addDataSource(CLEAN_UP_M2M_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.CLEAN_UP_M2M_USER_CSV));
        context.addDataSource(ROLE_TO_CREATE ,fromCsv(identityMgmtServiceRestConstants.FUNCTIONAL_TEST_USER_ROLE_CSV));
        context.addDataSource(ROLE_TO_DELETE ,fromCsv(identityMgmtServiceRestConstants.FUNCTIONAL_TEST_USER_ROLE_CSV));
        scenarioUtils.setupENMusers();
        scenarioUtils.cleanUpM2Musers();
    }

    @Test(enabled = true, priority = 1, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void createM2MUser() {
        context.addDataSource(CREATE_M2M_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.CREATE_M2M_USER_CSV));

        final TestScenario createM2MUser = dataDrivenScenario(CREATE_M2M_USER)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("1")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.createM2Muser().withDataSources(dataSource(CREATE_M2M_USER_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(createM2MUser);
    }

    @Test(enabled = true, priority = 2, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void checkM2MUser() {
        context.addDataSource(CHECK_M2M_USER_EXIST_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.CHECK_M2M_USER_CSV));

        final TestScenario checkM2MUser = dataDrivenScenario(CHECK_M2M_USER)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("2")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.checkM2MuserExist().withDataSources(dataSource(CHECK_M2M_USER_EXIST_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(checkM2MUser);
    }

    @Test(enabled = true, priority = 3, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void getM2MUser() {
        context.addDataSource(GET_M2M_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.GET_M2M_USER_CSV));

        final TestScenario getM2MUser = dataDrivenScenario(GET_M2M_USER)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("3")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.getM2Muser().withDataSources(dataSource(GET_M2M_USER_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(getM2MUser);
    }

    @Test(enabled = true, priority = 4, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void readM2MuserPassword() {
        context.addDataSource(GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.GET_UPDATE_M2M_USER_PASSWORD_CSV));

        final TestScenario readM2MuserPassword = dataDrivenScenario(GET_M2M_USER_PASSWORD)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("9")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.readM2MuserPassword().withDataSources(dataSource(GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(readM2MuserPassword);
    }

    @Test(enabled = true, priority = 5, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void updateM2MuserPassword() {
        context.addDataSource(GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.GET_UPDATE_M2M_USER_PASSWORD_CSV));

        final TestScenario updateM2MuserPassword = dataDrivenScenario(UPADATE_M2M_USER_PASSWORD)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("10")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.updateM2MuserPassword().withDataSources(dataSource(GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(updateM2MuserPassword);
    }

    @Test(enabled = true, priority = 6, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void createProxyUserAccount() {
        context.addDataSource(CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.CREATE_REMOVE_PROXY_ACCOUNT_CSV));

        final TestScenario createProxyUserAccount = dataDrivenScenario(CREATE_PROXY_ACCOUNT)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("11")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.creteProxyUserAccount().withDataSources(dataSource(CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(createProxyUserAccount);
    }

    @Test(enabled = true, priority = 7, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void deleteProxyUserAccount() {
        context.addDataSource(CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.CREATE_REMOVE_PROXY_ACCOUNT_CSV));

        final TestScenario deleteProxyUserAccount = dataDrivenScenario(DELETE_PROXY_ACCOUNT)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("12")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.deleteProxyUserAccount().withDataSources(dataSource(CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(deleteProxyUserAccount);
    }


    @Test(enabled = true, priority = 8, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void checkEnmUserHascomRole() {
        context.addDataSource(CHECK_COM_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.CHECK_COM_USER_CSV));

        final TestScenario checkEnmUserHasComRole = dataDrivenScenario(CHECK_COM_USER)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("6")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.checkEnmUserHasComRole().withDataSources(dataSource(CHECK_COM_USER_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(checkEnmUserHasComRole);
    }

    @Test(enabled = true, priority = 9, groups = { "Acceptance", "RFA250" })
    @TestSuite
    public void deleteM2Muser() {
        context.addDataSource(DELETE_M2M_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.DELETE_M2M_USER_CSV));

        final TestScenario deleteM2Muser = dataDrivenScenario(DELETE_M2M_USER)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("7")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.deleteM2Muser().withDataSources(dataSource(DELETE_M2M_USER_DATASOURCE)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(deleteM2Muser);
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // negative test performed with functional Test user without proper custom role assigned
    //
    @Test(enabled = true, priority = 9, groups = { "Acceptance", })
    @TestSuite
    public void userCannotAccessToRestAPI() {
        context.removeDataSource(CREATE_M2M_USER_DATASOURCE);
        context.removeDataSource(CHECK_M2M_USER_EXIST_DATASOURCE);
        context.removeDataSource(GET_M2M_USER_DATASOURCE);
        context.removeDataSource(GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE);
        context.removeDataSource(CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE);
        context.removeDataSource(CHECK_COM_USER_DATASOURCE);
        context.removeDataSource(DELETE_M2M_USER_DATASOURCE);

        context.addDataSource(CREATE_M2M_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.USER_CANNOT_ACCESS_TO_REST_API_CSV));
        context.addDataSource(CHECK_M2M_USER_EXIST_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.USER_CANNOT_ACCESS_TO_REST_API_CSV));
        context.addDataSource(GET_M2M_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.USER_CANNOT_ACCESS_TO_REST_API_CSV));
        context.addDataSource(GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.USER_CANNOT_ACCESS_TO_REST_API_CSV));
        context.addDataSource(CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.USER_CANNOT_ACCESS_TO_REST_API_CSV));
        context.addDataSource(CHECK_COM_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.USER_CANNOT_ACCESS_TO_REST_API_CSV));
        context.addDataSource(DELETE_M2M_USER_DATASOURCE, fromCsv(identityMgmtServiceRestConstants.USER_CANNOT_ACCESS_TO_REST_API_CSV));

        final TestScenario userCannotAccessToRestAPI = dataDrivenScenario(USER_CANNOT_ACCESS_TO_API)
                .withScenarioDataSources(dataSource(TEST_DATA_SOURCE).withFilter(testCaseIdFilter("8")))

                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("5"))

                .addFlow(identityManagementServiceRestFlow.createM2Muser().withDataSources(dataSource(CREATE_M2M_USER_DATASOURCE)
                        .withFilter(contextFilter("1"))))

                .addFlow(identityManagementServiceRestFlow.checkM2MuserExist().withDataSources(dataSource(CHECK_M2M_USER_EXIST_DATASOURCE)
                        .withFilter(contextFilter("2"))))

                .addFlow(identityManagementServiceRestFlow.getM2Muser().withDataSources(dataSource(GET_M2M_USER_DATASOURCE)
                        .withFilter(contextFilter("2"))))

                .addFlow(identityManagementServiceRestFlow.readM2MuserPassword().withDataSources(dataSource(GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE)
                        .withFilter(contextFilter("2"))))

                .addFlow(identityManagementServiceRestFlow.updateM2MuserPassword().withDataSources(dataSource(GET_UPDATE_M2MUSER_PASSWORD_DATASOURCE)
                        .withFilter(contextFilter("2"))))

                .addFlow(identityManagementServiceRestFlow.creteProxyUserAccount().withDataSources(dataSource(CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE)
                        .withFilter(contextFilter("3"))))

                .addFlow(identityManagementServiceRestFlow.deleteProxyUserAccountBasic().withDataSources(dataSource(CREATE_DELETE_PROXY_ACCOUNT_DATASOURCE)
                        .withFilter(contextFilter("3"))))

                .addFlow(identityManagementServiceRestFlow.checkEnmUserHasComRole().withDataSources(dataSource(CHECK_COM_USER_DATASOURCE)
                        .withFilter(contextFilter("4"))))

               .addFlow(identityManagementServiceRestFlow.deleteM2Muser().withDataSources(dataSource(DELETE_M2M_USER_DATASOURCE)
                        .withFilter(contextFilter("2"))))

                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(userCannotAccessToRestAPI);
    }
    //
    //  end negative test
    ////////////////////////////////////////////////////////////////////////////////////////

    @AfterClass(groups = { "Acceptance", "RFA250" }, alwaysRun = true)
    public void tearDown() throws TimeoutException, InterruptedException {
        scenarioUtils.tearDownScenario();
    }
}