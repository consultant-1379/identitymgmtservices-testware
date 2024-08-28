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
package com.ericsson.nms.security.taf.test.utility;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.impl.LoggingScenarioListener;
import com.ericsson.nms.security.taf.test.flows.IdentityManagementServicesTestFlow;
import com.ericsson.oss.testware.nodesecurity.flows.IdentityManagementServiceRestFlow;
import com.ericsson.oss.testware.nodesecurity.flows.PibFlows;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.ericsson.oss.testware.security.gim.flows.RoleManagementTestFlows;
import com.ericsson.oss.testware.security.gim.flows.UserManagementTestFlows;
import com.google.common.base.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.runner;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler.LOGONLY;

public class identityMgmtServiceRestScenarioUtils {

    private static final Logger log = LoggerFactory.getLogger(identityMgmtServiceRestScenarioUtils.class);

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private IdentityManagementServicesTestFlow identityManagementServicesTestFlow;

    @Inject
    private IdentityManagementServiceRestFlow identityManagementServiceRestFlow;

    @Inject
    private RoleManagementTestFlows roleManagementTestFlows;

    @Inject
    private UserManagementTestFlows userManagementTestFlows;

    @Inject
    private PibFlows pibFlow;



    public static Predicate<DataRecord> contextFilter(final String i) {

        final Predicate<DataRecord> getIthRecord = new Predicate<DataRecord>() {
            @Override
            public boolean test(final DataRecord dataRecord) {
                final String context = dataRecord.getFieldValue("context");
                return context.equals(i);
            }
            @Override
            public boolean apply(final DataRecord dataRecord) {
                final String context = dataRecord.getFieldValue("context");
                return context.equals(i);
            }
        };
        return getIthRecord;
    }

    public static Predicate<DataRecord> testCaseIdFilter(final String i) {

        final Predicate<DataRecord> getIthRecord = new Predicate<DataRecord>() {
            @Override
            public boolean test(final DataRecord dataRecord) {
                final String context = dataRecord.getFieldValue("testId");
                return context.equals(i);
            }
            @Override
            public boolean apply(final DataRecord dataRecord) {
                final String testId = dataRecord.getFieldValue("testId");
                return testId.equals(i);
            }
        };
        return getIthRecord;
    }

    public static void executeScenario(final TestScenario scenario) {
        final TestScenarioRunner runner = getScenarioRunner();
        runner.start(scenario);
    }

    public static TestScenarioRunner getScenarioRunner() {
        return runner().withListener(new LoggingScenarioListener()).build();
    }


    public void setupENMusers() {
        final TestScenario setupCreateENMusers = scenario("setUp Scenario - create ENM users")
                .addFlow(userManagementTestFlows.deleteUser()) // delete ENM users (including functional test user) if exist
                .addFlow(roleManagementTestFlows.deleteRole()) // delete "Security-IdentityMgmt Custom Role" if exist
                .addFlow(roleManagementTestFlows.createRole()) // create "Security-IdentityMgmt Custom Role" with capability
                .addFlow(pibFlow.delay(180, "- Delay after custom role creation"))
                .addFlow(userManagementTestFlows.createUser()) // create ENM users
                .withExceptionHandler(LOGONLY)
                .build();
        executeScenario(setupCreateENMusers);
    }

    public void cleanUpM2Musers() {
        final TestScenario setupCleanUpM2Musers = scenario("setUp Scenario - cleanUp m2m users")
                .addFlow(identityManagementServicesTestFlow.loginFunctionalUser("4"))
                .addFlow(identityManagementServiceRestFlow.cleanUpM2Muser()) // delete any m2m users if exist
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(setupCleanUpM2Musers);
    }

    public void tearDownScenario() {
        final TestScenario scenario = scenario("tear down Scenario - remove ENM users")
                .addFlow(userManagementTestFlows.deleteUser())
                .addFlow(roleManagementTestFlows.deleteRole())
                .build();
        executeScenario(scenario);
    }

}