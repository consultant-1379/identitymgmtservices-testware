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
package com.ericsson.nms.security.taf.test.cases;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.*;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.taf.test.flows.IdentityManagementServicesTestFlow.*;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.inject.Inject;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.*;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.DataDriven;
import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.Output;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.data.Host;
import com.ericsson.cifwk.taf.data.pool.DataPoolStrategy;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.impl.LoggingScenarioListener;
import com.ericsson.cifwk.taf.tools.cli.TimeoutException;
import com.ericsson.cifwk.taf.utils.FileFinder;
import com.ericsson.nms.security.taf.test.flows.IdentityManagementServicesTestFlow;
import com.ericsson.nms.security.taf.test.operators.CliOperator;
import com.ericsson.nms.security.taf.test.operators.CliOperatorImpl;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;
import com.ericsson.oss.testware.security.gim.flows.GimCleanupFlows;
import com.ericsson.oss.testware.security.gim.flows.GimCleanupFlows.EnmObjectType;
import com.ericsson.oss.testware.security.gim.flows.UserManagementTestFlows;
@Deprecated
public class IDMServiceRestTest extends TafTestBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(IDMServiceRestTest.class);
    private static final String GLOBAL_PROPERTIES_FILE = "/ericsson/tor/data/global.properties";
    private static final String DECRYPT_OPENDJ_PWD_FILE = "decryptOpenDJAdminPwd.sh";
    private static final String DECRYPT_OPENIDM_PWD_FILE = "decryptOpenIDMSecAdminPwd.sh";
    private static final String ROOT_SUFFIX_VARIABLE = "COM_INF_LDAP_ROOT_SUFFIX";
    private static final String OPENIDM_ADMIN_PWD_VARIABLE = "OPENIDM_ADMIN_PASSWORD";
    private static final String OPENDJ_ADMIN_PWD_VARIABLE = "OPENDJ_ADMIN_PASSWORD";
    private static final String MOD_CLUSTER_HTTPD_HOSTNAME_VARIABLE = "HTTPD_HOST_NAME";
    private static final String COOKIE_FILE_VARIABLE = "COOKIE_FILE";
    private static String rootSuffixValue;
    private static String nodeHostName;
    private static String httpdHostName;
    private static String testHostName;
    private static String cookieFileName = "/tmp/cookieForIdmTaf.txt";

    @Inject
    transient private CliOperatorImpl cliOperator;

    @Inject
    private TestContext context;

    private TestScenarioRunner runner;

    @Inject
    private GimCleanupFlows idmCleanupFlows;

    @Inject
    private UserManagementTestFlows userManagementFlows;

    @Inject
    private IdentityManagementServicesTestFlow identityManagementServicesTestFlow;

    @BeforeClass
    public void suiteSetup() throws TimeoutException, FileNotFoundException, IOException {
        LOGGER.info("Before suite: Cli operators setup and password decryption");

        // attempt to initialize shell on sc1 or svc1 .. initializeShell will
        // switch to the other one if sc1 is unavailable.
        nodeHostName = cliOperator.initializeShell(HostConfigurator.getMS().getHostname());

        LOGGER.info("suiteSetup: host = " + nodeHostName);
        assertNotNull("suiteSetup: host to initialize Shell", nodeHostName);

        uploadFile(DECRYPT_OPENDJ_PWD_FILE, nodeHostName, "/tmp", cliOperator);
        DataHandler.setAttribute(OPENDJ_ADMIN_PWD_VARIABLE, decryptPassword("decryptOpenDJAdminPwd", cliOperator));

        uploadFile(DECRYPT_OPENIDM_PWD_FILE, nodeHostName, "/tmp", cliOperator);
        DataHandler.setAttribute(OPENIDM_ADMIN_PWD_VARIABLE, decryptPassword("decryptOpenIDMSecAdminPwd", cliOperator));

        rootSuffixValue = readGlobalProperties(cliOperator, ROOT_SUFFIX_VARIABLE, null);
        assertTrue("Assertion failed, incorrect root suffix length", rootSuffixValue.length() > 0);

        httpdHostName = identifyHttpdHostName(cliOperator);

        LOGGER.info("suiteSetup: httpd hostname for IDM Rest Interface tests = " + httpdHostName);
        assertNotNull("suiteSetup: httpd host for IDM Rest Interface ", httpdHostName);

        DataHandler.setAttribute(MOD_CLUSTER_HTTPD_HOSTNAME_VARIABLE, httpdHostName);

        DataHandler.setAttribute(COOKIE_FILE_VARIABLE, cookieFileName);

        cliOperator.writeln("exit");
        cliOperator.expectClose(10000);
        assertTrue("Assertion failed, cliOperator not closed", cliOperator.isClosed());
        assert cliOperator.getExitValue() == 0;
        cliOperator.disconnect();
    }

    @AfterClass(alwaysRun = true)
    public void suiteTearDown() {
        LOGGER.info("After suite: Cli operators teardown and file cleaning");

        nodeHostName = cliOperator.initializeShell(nodeHostName);
        assertNotNull("suiteTearDown initializing Shell", nodeHostName);

        deleteFile(DECRYPT_OPENDJ_PWD_FILE, "/tmp", cliOperator);
        deleteFile(DECRYPT_OPENIDM_PWD_FILE, "/tmp", cliOperator);

        cliOperator.writeln("exit");
        cliOperator.expectClose(10000);
        assertTrue("Assertion failed, cliOperator not closed", cliOperator.isClosed());
        assert cliOperator.getExitValue() == 0;
        cliOperator.disconnect();
    }

    /**
     * @DESCRIPTION Upload the file needed to host connected with the cli operator
     */
    private void uploadFile(final String fileName, final String hostName, final String directory, final CliOperator cliOperator)
            throws TimeoutException, FileNotFoundException, IOException {
        LOGGER.info("Setup: Uploading " + fileName + " to " + hostName + "...");

        final String filePath = FileFinder.findFile(fileName + ".repo").get(0);
        final String fileContent = FileUtils.readFileToString(new File(filePath));
        final String tempFilePath = filePath.replace(".repo", "");
        final File tempFile = new File(tempFilePath);
        FileUtils.writeStringToFile(tempFile, fileContent);

        cliOperator.sendFileRemotely(hostName, fileName, directory);
        cliOperator.writeln("change.dir", directory);
        cliOperator.writeln("list.dir");
        final String stdout = cliOperator.getStdOut();
        assertTrue("Assertion failed, file not uploaded", stdout.contains(fileName));
        LOGGER.info(stdout);
        tempFile.delete();

        LOGGER.info("Setup: Uploading " + fileName + " done");
    }

    /**
     * @DESCRIPTION decrypt the password
     */
    private String decryptPassword(final String command, final CliOperator cliOperator) {
        LOGGER.info("decryptPassword: " + command);

        cliOperator.writeln(command);
        final String stdout = cliOperator.getStdOut();
        final String password = stdout.split(System.getProperty("line.separator"))[1].trim();
        assertTrue("Assertion failed, incorrect password length", password.length() > 0);

        LOGGER.info("decryptPassword: " + command + "done");
        return password;
    }

    /**
     * @DESCRIPTION delete file through cli operator
     */
    private void deleteFile(final String fileName, final String directory, final CliOperator cliOperator) {
        LOGGER.info("Cleaning " + fileName);

        cliOperator.writeln("change.dir", directory);
        cliOperator.writeln("delete", fileName);

        LOGGER.info("Cleaning " + fileName + "done");
    }

    /*
     * This is a prep test case which is executed to create a user which is added to OpenIDM and later sync into openDJ. Command and its data is
     * defined in IDMServiceRest_Login.csv file. curl command is used to add the user.
     */
    @TestId(id = "TORF-52978_func_3", title = "login to ENM to obtain cookie")
    @Test(groups = { "Acceptance", "RFA" })
    @DataDriven(name = "IDMServiceRest_Login")
    public void loginToENM(@Input("step") final String step, @Input("host") final String hostname, @Input("command") final String command,
                           @Input("timeout") final int timeout, @Input("args") final String args) throws InterruptedException, TimeoutException {

        LOGGER.info("Test Step: " + step);

        testHostName = cliOperator.initializeShell("svc1");

        assertNotNull("loginToENM initializing Shell", testHostName);

        //run curl command with username and password to ENM login page
        cliOperator.writeln(command, updateTestVariables(args));

        //verify that cookie file gets created
        cliOperator.writeln("list.dir", cookieFileName);
        final String output = cliOperator.getStdOut();
        assertTrue("Assertion failed, cookie not created", output.contains(cookieFileName));

        LOGGER.info("Done Test Step: " + step + ". Actual output:" + output);
        cliOperator.writeln("exit");
        cliOperator.expectClose(timeout);
        assertTrue("Assertion failed, cliOperator not closed", cliOperator.isClosed());
        assert cliOperator.getExitValue() == 0;
        cliOperator.disconnect();
    }

    /*
     * This is a prep test case which is executed to create a user which is added to OpenIDM and later sync into openDJ. Command and its data is
     * defined in IDMServiceRest_User.csv file.
     */
    @TestId(id = "TORF-52978_func_4", title = "create a fieldTech user")
    @Test(groups = { "Acceptance", "RFA" })
    public void createUser() {
        LOGGER.info("Start scenario createUser");
        context.addDataSource(USERS_TO_CREATE, TafDataSources.shared(TafDataSources.fromCsv("data/IDMServiceRest_User.csv")));
        context.addDataSource(USER_TO_CLEAN_UP, shared(fromCsv("data/IDMServiceRest_User.csv", DataPoolStrategy.STOP_ON_END)));

        final TestScenario scenario = scenario("Create User test").addFlow(idmCleanupFlows.cleanUp(EnmObjectType.USER))
                .addFlow(userManagementFlows.createUser()).build();

        runner = runner().withListener(new LoggingScenarioListener()).build();

        runner.start(scenario);
    }

    /*
     * This is a functional test to verify addPosixAttributes method. Various input data are loaded from IDMServiceRest_AddPosixAttributes.csv file.
     */
    @TestId(id = "TORF-52978_func_1", title = "idmservice_rest_addPosixAttributes")
    @Test(groups = { "Acceptance", "RFA" })
    @DataDriven(name = "IDMServiceRest_AddPosixAttributes")
    public void verifyAddPosixAttributes(@Input("step") final String step, @Input("command") final String command, @Input("args") final String args,
                                         @Output("expectedOut") final String expectedOut, @Input("timeout") final int timeout)
                                                 throws InterruptedException, TimeoutException {
        checkPosixAttributes(step, command, args, expectedOut, timeout, "verifyAddPosixAttributes");
    }

    /*
     * This is a functional test to verify addPosixAttributesAmosAndEM method. Various input data are loaded from
     * IDMServiceRest_AddPosixAttributesAmosAndEM.csv file.
     */
    @TestId(id = "TORF-52978_func_5", title = "idmservice_rest_addPosixAttributesAmosAndEM")
    @Test(groups = { "Acceptance", "RFA" })
    @DataDriven(name = "IDMServiceRest_AddPosixAttributesAmosAndEM")
    public void verifyAddPosixAttributesAmosAndEM(@Input("step") final String step, @Input("command") final String command,
                                                  @Input("args") final String args, @Output("expectedOut") final String expectedOut,
                                                  @Input("timeout") final int timeout) throws InterruptedException, TimeoutException {
        checkPosixAttributes(step, command, args, expectedOut, timeout, "verifyAddPosixAttributesAmosAndEM");
    }

    /*
     * This is a functional test to verify addPosixAttributesSmrsAndAmosAndEM method. Various input data are loaded from
     * IDMServiceRest_AddPosixAttributesSmrsAndAmosAndEM.csv file.
     */
    @TestId(id = "TORF-52978_func_6", title = "idmservice_rest_addPosixAttributesSmrsAndAmosAndEM")
    @Test(groups = { "Acceptance", "RFA" })
    @DataDriven(name = "IDMServiceRest_AddPosixAttributesSmrsAndAmosAndEM")
    public void verifyAddPosixAttributesSmrsAndAmosAndEM(@Input("step") final String step, @Input("command") final String command,
                                                         @Input("args") final String args, @Output("expectedOut") final String expectedOut,
                                                         @Input("timeout") final int timeout) throws InterruptedException, TimeoutException {
        checkPosixAttributes(step, command, args, expectedOut, timeout, "verifyAddPosixAttributesSmrsAndAmosAndEM");
    }

    /*
     * This is a functional test to verify removePosixAttributes method. Various input data are loaded from IDMServiceRest_RemovePosixAttributes.csv
     * file.
     */
    @TestId(id = "TORF-52978_func_2", title = "idmservice_rest_removePosixAttributes")
    @Test(groups = { "Acceptance", "RFA" })
    @DataDriven(name = "IDMServiceRest_RemovePosixAttributes")
    public void verifyRemovePosixAttributes(@Input("step") final String step, @Input("command") final String command,
                                            @Input("args") final String args, @Output("expectedOut") final String expectedOut,
                                            @Input("timeout") final int timeout) throws InterruptedException, TimeoutException {
        checkPosixAttributes(step, command, args, expectedOut, timeout, "verifyRemovePosixAttributes");
    }

    /*
     * This is a functional test to verify addPosixAttributesAmosAndEM method. Various input data are loaded from
     * IDMServiceRest_AddPosixAttributesAmosAndEM.csv file.
     */
    @TestId(id = "TORF-52978_func_7", title = "idmservice_rest_removePosixAttributesAmosAndEM")
    @Test(groups = { "Acceptance", "RFA" })
    public void verifyRemovePosixAttributesAmosAndEM() {
        LOGGER.info("Start scenario verifyRemovePosixAttributesAmosAndEM");
        context.addDataSource(POSIX_ATTRIBUTE_TO_DELETE,
                TafDataSources.shared(TafDataSources.fromCsv("data/IDMServiceRest_RemovePosixAttributesAmosAndEM.csv")));

        final TestScenario scenario = scenario("Remove Posix Attributes test").addFlow(identityManagementServicesTestFlow.removePosixAttributes())
                .build();

        runner = runner().withListener(new LoggingScenarioListener()).build();

        runner.start(scenario);
    }

    /*
     * This is a functional test to verify removePosixAttributesEMAndAmosAndSmrs method. Various input data are loaded from
     * IDMServiceRest_RemovePosixAttributesEMAndAmosAndSmrs.csv file.
     */
    @TestId(id = "TORF-52978_func_8", title = "idmservice_rest_removePosixAttributesEMAndAmosAndSmrs")
    @Test(groups = { "Acceptance", "RFA" })
    @DataDriven(name = "IDMServiceRest_RemovePosixAttributesEMAndAmosAndSmrs")
    public void verifyRemovePosixAttributesEMAndAmosAndSmrs(@Input("step") final String step, @Input("command") final String command,
                                                            @Input("args") final String args, @Output("expectedOut") final String expectedOut,
                                                            @Input("timeout") final int timeout) throws InterruptedException, TimeoutException {
        checkPosixAttributes(step, command, args, expectedOut, timeout, "verifyRemovePosixAttributesEMAndAmosAndSmrs");
    }

    /*
     * This is a post step for cleaning up.
     */
    @TestId(id = "TORF-52978_func_9", title = "delete the test user")
    @Test(groups = { "Acceptance", "RFA" })
    public void deleteUser() {
        LOGGER.info("Start scenario deleteUser");
        context.addDataSource(USERS_TO_DELETE, TafDataSources.shared(TafDataSources.fromCsv("data/IDMServiceRest_User.csv")));

        final TestScenario scenario = scenario("Delete User test").addFlow(userManagementFlows.deleteUser()).build();

        runner = runner().withListener(new LoggingScenarioListener()).build();

        runner.start(scenario);
    }

    private void checkPosixAttributes(final String step, final String command, final String args, final String expectedOut, final int timeout,
                                      final String testMethodName) {
        LOGGER.info("Test Step: " + step + " arg:" + args + ", expectedOut: " + expectedOut);

        testHostName = cliOperator.initializeShell(testHostName);
        assertNotNull(testMethodName + "  initializing Shell", testHostName);

        cliOperator.writeln(command, updateTestVariables(args));

        final String output = cliOperator.getStdOut();
        LOGGER.info("Done Test Step: " + step + ". Actual output:" + output);
        assertTrue("Assertion failed, output does not contains expected output", output.contains(updateTestVariables(expectedOut)));

        cliOperator.writeln("exit");
        cliOperator.expectClose(timeout);
        assertTrue("Assertion failed, cliOperator not closed", cliOperator.isClosed());
        assert cliOperator.getExitValue() == 0;
        cliOperator.disconnect();
    }

    /**
     * The private method executes command and wait for prompt. It prevents cli freezing.
     */
    private String writeCommandAndWaitForOutput(final String command, final String args) throws InterruptedException {
        cliOperator.writeln(command, args);
        String output = "";
        final int maxIteration = 10;
        final int sleepInMs = 1000;

        for (int i = 0; i < maxIteration; i++) {
            output += cliOperator.getStdOut();
            LOGGER.info("Waiting for output");
            if (output.contains("$")) {
                break;
            }
            Thread.sleep(sleepInMs);
        }
        return output;
    }

    /**
     * The private method to execute the command. It is common for most of the test cases. However, for some test cases that needs additional
     * information, this method cannot be reused.
     */
    private void runCommands(final String step, final String hostname, final String command, final int timeout, final String args,
                             final String expectedOut, final int expectedExitCode) {
        LOGGER.info("Test Step: " + step);

        cliOperator.initializeShell(hostname);

        final String expectedOutUpdated = updateTestVariables(expectedOut);

        cliOperator.writeln(command, updateTestVariables(args));

        final String output = cliOperator.getStdOut();
        if (expectedOutUpdated != null && !expectedOutUpdated.isEmpty()) {
            assertTrue("Assertion failed, output does not contains expected output", output.contains(expectedOutUpdated));
        } else if (expectedOutUpdated != null && expectedOutUpdated.isEmpty()) {
            //if the expectedOut is an empty string, if must means that there is no error
            assertFalse("Assertion failed, output contains 'error'", output.contains("\"error\""));
        }

        cliOperator.writeln("exit");
        cliOperator.expectClose(timeout);
        assertTrue("Assertion failed, cliOperator not closed", cliOperator.isClosed());
        assert cliOperator.getExitValue() == expectedExitCode;
        cliOperator.disconnect();
    }

    /**
     * The private method to execute the command. It is common for most of the test cases. However, for some test cases that needs additional
     * information, this method cannot be reused.
     */
    private void runCommandsWithExitCode(final String step, final String hostname, final String command, final int timeout, final String args,
                                         final int expectedOutCode, final int expectedExitCode) {
        runCommandsWithExitCode(step, hostname, command, timeout, args, null, expectedOutCode, expectedExitCode);
    }

    /**
     * The private method to execute the command. It is common for most of the test cases. However, for some test cases that needs additional
     * information, this method cannot be reused.
     */
    private void runCommandsWithExitCode(final String step, final String hostname, final String command, final int timeout, final String args,
                                         final String expectedOut, final int expectedOutCode, final int expectedExitCode) {
        LOGGER.info("Test Step: " + step);
        cliOperator.initializeShell(hostname);

        cliOperator.writeln(command, updateTestVariables(args));

        final String output = cliOperator.getStdOut();
        LOGGER.info("Test Step: " + step + " output:" + output);
        if (expectedOut != null && !expectedOut.isEmpty()) {
            assertTrue("Assertion failed, output does not contains expected output", output.contains(expectedOut));
        } else if (expectedOut != null && expectedOut.isEmpty()) {
            //if the expectedOut is an empty string, if must means that there is no error
            assertFalse("Assertion failed, output contains 'error'", output.contains("\"error\""));
        }

        assert cliOperator.getExitValue() == expectedOutCode;

        cliOperator.writeln("exit");
        cliOperator.expectClose(timeout);
        assertTrue("Assertion failed, cliOperator not closed", cliOperator.isClosed());
        assert cliOperator.getExitValue() == expectedExitCode;
        cliOperator.disconnect();
    }

    private String readGlobalProperties(final CliOperator cliOperator, final String property, final String args) {
        cliOperator.writeln("source", GLOBAL_PROPERTIES_FILE);
        if (args == null) {
            cliOperator.writeln("echo", "$" + property);
        } else {
            cliOperator.writeln("echo", "$" + property + " " + args);
        }
        return cliOperator.getStdOut().split(System.getProperty("line.separator"))[2].trim();
    }

    private String updateTestVariables(final String data) {
        if (data == null) {
            return null;
        }
        String result = data;
        if (data.contains(ROOT_SUFFIX_VARIABLE)) {
            result = result.replace(ROOT_SUFFIX_VARIABLE, rootSuffixValue);
        }
        if (data.contains(OPENIDM_ADMIN_PWD_VARIABLE)) {
            result = result.replace(OPENIDM_ADMIN_PWD_VARIABLE, DataHandler.getAttribute(OPENIDM_ADMIN_PWD_VARIABLE).toString());
        }
        if (data.contains(OPENDJ_ADMIN_PWD_VARIABLE)) {
            result = result.replace(OPENDJ_ADMIN_PWD_VARIABLE, DataHandler.getAttribute(OPENDJ_ADMIN_PWD_VARIABLE).toString());
        }
        if (data.contains(MOD_CLUSTER_HTTPD_HOSTNAME_VARIABLE)) {
            result = result.replace(MOD_CLUSTER_HTTPD_HOSTNAME_VARIABLE, DataHandler.getAttribute(MOD_CLUSTER_HTTPD_HOSTNAME_VARIABLE).toString());
        }
        if (data.contains(COOKIE_FILE_VARIABLE)) {
            result = result.replace(COOKIE_FILE_VARIABLE, DataHandler.getAttribute(COOKIE_FILE_VARIABLE).toString());
        }
        return result;
    }

    private String identifyHttpdHostName(final CliOperator cliOperator) {
        LOGGER.info("Identifying HTTPD HOST to access OpenIDM to add/remove user :");
        final Host apacheHost = HostConfigurator.getApache();
        LOGGER.info("Apache hostname: " + apacheHost.getHostname());
        LOGGER.info("Apache IP: " + apacheHost.getIp());
        //String hostName = "enmapache.athtem.eei.ericsson.se";
        final String hostName = apacheHost.getIp();
        LOGGER.info("HttpdHostName to use: " + hostName);
        return hostName;
    }

}