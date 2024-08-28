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

import static java.lang.Thread.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.rmi.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.DataDriven;
import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.Output;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.data.Host;
import com.ericsson.cifwk.taf.data.User;
import com.ericsson.cifwk.taf.data.UserType;
import com.ericsson.cifwk.taf.tools.cli.CLICommandHelper;
import com.ericsson.cifwk.taf.tools.cli.Shell;
import com.ericsson.cifwk.taf.tools.cli.handlers.impl.RemoteObjectHandler;
import com.ericsson.nms.security.taf.test.operators.CliOperatorImpl;
import com.ericsson.nms.security.taf.test.operators.IMServiceApiOperator;
import com.ericsson.oss.itpf.security.identitymgmtservices.IdentityManagementServiceException;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;
@Deprecated
public class IMService_FunctionalTest extends TafTestBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(IMService_FunctionalTest.class);

    private static final String TEST_FILE_NAME = "idmts_testdata.txt";

    @Inject
    private IMServiceApiOperator iMServiceOperator;

    @Inject
    private CliOperatorImpl cliOperator;

    /**
     * @DESCRIPTION Verify correct functioning of create Proxy agent. Test creates ProxyAccount then check if proper LDAP entry is added.
     *
     * @PRIORITY HIGH
     */
    @TestId(id = "createProxyAgent", title = "Create Proxy agent")
    @DataDriven(name = "imservice_functionaltest_create_proxy_agent")
    @Test(groups = { "Acceptance", "RFA" })
    public void createProxyAgent(@Input("expected") final String expected) {

        String proxyAgentDN = null;
        String result = null;
        try {
            LOGGER.info("Test createProxyAgent: start");
            LOGGER.info("Create ProxyAgent:");
            proxyAgentDN = iMServiceOperator.createProxyAgent();
            LOGGER.info("ProxyAgent created: {}", proxyAgentDN);
            LOGGER.info("Check if ProxyAgent: {} exists in LDAP", proxyAgentDN);

            final String regExp = "cn=(.*),ou=(.*),ou=(.*),dc=(.*),dc=(.*)";
            final Pattern pattern = Pattern.compile(regExp);
            final Matcher matcher = pattern.matcher(proxyAgentDN);
            matcher.matches();
            final String userName = matcher.group(1);

            LOGGER.info("Initial db1");
            cliOperator.initializeShell("db1");
            LOGGER.info("Initial complete");
            LOGGER.info("LDAP search start");
            final String output = ldapSearchUserFull(userName);
            LOGGER.info("LDAP search output: {}", output);
            result = (output.contains(("dn: " + proxyAgentDN))) ? "TRUE" : "FALSE";
            LOGGER.info("Test createProxyAgent result: {}", result);
            assertEquals(expected, result);
            LOGGER.info("Finish test: createProxyAgent");
        } finally {
            LOGGER.info("Clean up after test createProxyAgent");
            ldapDeleteUserFull(proxyAgentDN);
            cliOperator.disconnect();
        }
    }

    /**
     * @DESCRIPTION Verify correct functioning of delete proxy agent. Test creates ProxyAccount, delete it and check if proper LDAP entry is removed.
     *
     * @PRIORITY HIGH
     */
    @TestId(id = "deleteProxyAgent", title = "delete proxy agent")
    @DataDriven(name = "imservice_functionaltest_delete_proxy_agent")
    @Test(groups = { "Acceptance", "RFA" }/* , dependsOnMethods = { "createProxyAgent" } */)
    public void deleteProxyAgent(@Input("expected") final String expected) {
        String proxyAgentDN = null;
        String result = null;
        try {
            LOGGER.info("Test deleteProxyAgent: start");
            LOGGER.info("Create ProxyAgent");
            proxyAgentDN = iMServiceOperator.createProxyAgent();
            LOGGER.info("ProxyAgent created: {}", proxyAgentDN);
            LOGGER.info("Request of delete proxy agent");
            iMServiceOperator.deleteProxyAgent(proxyAgentDN);
            LOGGER.info("Check if ProxyAgent: {} exists in LDAP", proxyAgentDN);

            final String regExp = "cn=(.*),ou=(.*),dc=(.*),dc=(.*)";
            final Pattern pattern = Pattern.compile(regExp);
            final Matcher matcher = pattern.matcher(proxyAgentDN);
            matcher.matches();
            final String userName = matcher.group(1);
            LOGGER.info("initial of db1");
            cliOperator.initializeShell("db1");
            LOGGER.info("search for DC: {}", searchForDc());
            final String output = ldapSearchUserFull(userName);
            LOGGER.info("LDAP search output: " + output);
            result = (output.contains(("dn: " + proxyAgentDN))) ? "TRUE" : "FALSE";
            LOGGER.info("Test deleteProxyAgent result: {}", result);
            assertEquals(expected, result);
            LOGGER.info("Test deleteProxyAgent: finish");
        } finally {
            LOGGER.info("Clean up after test deleteProxyAgent");
            ldapDeleteUserFull(proxyAgentDN);
            cliOperator.disconnect();
        }
    }

    /*
     * Remove any test users that exist
     */
    @TestId(id = "TORF-11465_Func_12", title = "Remove test users")
    @DataDriven(name = "imservice_functionaltest_users")
    @Test(groups = { "Acceptance", "RFA" })
    public void cleanUpM2MUser(@Input("userName") final String user) {
        LOGGER.debug("call cleanup on ", user);
        assertEquals("SUCCESS", iMServiceOperator.cleanUp(user));
    }

    /**
     * @DESCRIPTION Verify correct functioning of create M2M user request
     * @PRE IM service is running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-11465_Func_8", title = "Create M2M user")
    @DataDriven(name = "imservice_functionaltest_create")
    @Test(groups = { "Acceptance", "RFA" }, dependsOnMethods = { "cleanUpM2MUser" })
    public void createM2MUser(@Input("userName") final String userName, @Input("groupName") final String groupName,
                              @Input("homeDir") final String homeDir, @Input("validDays") final String validDays,
                              @Output("expected") final String expected) {

        LOGGER.debug("createM2MUser: start");
        LOGGER.info("Request creation of user");
        final String result = iMServiceOperator.createM2MUser(userName, groupName, homeDir, validDays);

        assertEquals(expected, result);
    }

    /**
     * @DESCRIPTION Verify correct functioning of M2M user existence request
     * @PRE IM service is running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-11465_Func_9", title = "Check M2M user existence")
    @DataDriven(name = "imservice_functionaltest_exists")
    @Test(groups = { "Acceptance", "RFA" }, dependsOnMethods = { "createM2MUser" })
    public void checkM2MUserExistence(@Input("userName") final String userName, @Output("expected") final String expected) {
        LOGGER.info("Query existence of user");

        assertEquals(expected, iMServiceOperator.isExistingM2MUser(userName));
    }

    /**
     * @DESCRIPTION Verify correct functioning of get M2M user request
     * @PRE IM service is running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-11465_Func_10", title = "Get M2M user")
    @DataDriven(name = "imservice_functionaltest_get")
    @Test(groups = { "Acceptance", "RFA" }, dependsOnMethods = { "checkM2MUserExistence" })
    public void getM2MUser(@Input("userName") final String userName, @Output("expected") final String expected) {
        LOGGER.info("Request user info");

        assertEquals(expected, iMServiceOperator.getM2MUser(userName));
    }

    /**
     * @DESCRIPTION Verify correct functioning of delete M2M user request
     * @PRE IM service is running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-11465_Func_11", title = "Delete M2M user")
    @DataDriven(name = "imservice_functionaltest_delete")
    @Test(groups = { "Acceptance", "RFA" }, dependsOnMethods = { "getM2MUser" })
    public void deleteM2MUser(@Input("userName") final String userName, @Output("expected") final String expected) {
        LOGGER.info("Request deletion of user");

        assertEquals(expected, iMServiceOperator.deleteM2MUser(userName));
    }

    /**
     * @DESCRIPTION Test case to get the M2M user password request
     * @PRE IM Service is running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-13533_Func_1", title = "Get M2M Password")
    @DataDriven(name = "imservice_functionaltest_getpwd")
    @Test(groups = { "Acceptance", "RFA" }, dependsOnMethods = { "checkM2MUserExistence" })
    public void getM2MPassword(@Input("userName") final String userName, @Output("expected") final String expected) {
        LOGGER.info("To return the user password");

        assertEquals(expected, iMServiceOperator.getM2MPassword(userName));
    }

    /**
     * @DESCRIPTION Test case to update the M2M user password request
     * @PRE IM Service is running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-13533_Func_2", title = "Update M2M Password")
    @DataDriven(name = "imservice_functionaltest_updatepwd")
    @Test(groups = { "Acceptance", "RFA" }, dependsOnMethods = { "checkM2MUserExistence" })
    public void updateM2MPassword(@Input("userName") final String userName, @Output("expected") final String expected) {
        LOGGER.info("update M2M user password");

        assertEquals(expected, iMServiceOperator.updateM2MPassword(userName));
    }

    /**
     * @DESCRIPTION Test case to verify that valid M2M user can access to ENM using sftp
     * @PRE IM Service is running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-36344", title = "Check M2M SFTP")
    @DataDriven(name = "imservice_functionaltest_sftptosc")
    @Test(groups = { "Acceptance", "RFA" })
    public void verifyValidM2MUserCanSftpToSc(@Input("nodeHost") final String nodeHost, @Input("userGroup") final String userGroup,
                                              @Input("smrsAccountName") final String smrsAccountName,
                                              @Input("smrsHomeDirectory") final String smrsHomeDirectory, @Input("validTime") final String validTime,
                                              @Output("result") final boolean result) throws UnknownHostException {
        final int repeatMax = 3;
        final int timeInSeconds = 10;
        boolean didLocalToRemoteCopyWork = false;
        boolean didDeleteWork = false;
        boolean didRemoteToLocalCopyWork = false;
        boolean directoryCreated = true;

        iMServiceOperator.createM2MUser(smrsAccountName, userGroup, smrsHomeDirectory, validTime);

        LOGGER.debug("Verifying that user " + smrsAccountName + " can sftp to " + nodeHost);

        boolean userExists = false;
        char[] userPassword = null;
        final StringBuilder passwordString = new StringBuilder();

        try {
            cliOperator.initializeShell(("secServ_1"));
            directoryCreated = ensureDesiredDirectoryExist(smrsHomeDirectory);
            if (directoryCreated) {
                cliOperator.writeln("setfacl", "-m g::rwx " + smrsHomeDirectory);
                cliOperator.writeln("setfacl", "-m g:mm-smrsusers:rwx " + smrsHomeDirectory);
                cliOperator.writeln("setfacl", "-d -m u::rwx " + smrsHomeDirectory);
                cliOperator.writeln("setfacl", "-d -m g:mm-smrsusers:rwx " + smrsHomeDirectory);
            }

            LOGGER.debug("Checking if User: " + smrsAccountName + " exists in IDM");

            userExists = iMServiceOperator.isExistingM2MUser(smrsAccountName).equals("true");

            if (userExists) {
                try {
                    LOGGER.debug("Getting user password for " + smrsAccountName);
                    userPassword = iMServiceOperator.getM2MPasswordAsCharArray(smrsAccountName);
                    assertNotNull("User password is null", userPassword);
                    passwordString.append(userPassword);
                } catch (final IdentityManagementServiceException e) {
                    LOGGER.error("Error attempting get user password for " + smrsAccountName);
                    fail();
                }
            } else {
                LOGGER.error(smrsAccountName + " user doesn't exist.");
                fail();
            }

        } catch (final IdentityManagementServiceException e) {
            LOGGER.error("Error reading user from the Identity Management Service: " + e);
        } finally {
            cliOperator.disconnect();
        }

        final Host remoteHost = cliOperator.getSecServInternal();

        final String relativePath = smrsHomeDirectory.substring(10);

        LOGGER.info("relativepath to file: {}", relativePath);
        final List<User> users = new LinkedList<>();
        final User m2mUser = new User(smrsAccountName, passwordString.toString(), UserType.CUSTOM);
        users.add(m2mUser);
        users.addAll(remoteHost.getUsers());
        remoteHost.setUsers(users);
        RemoteObjectHandler remoteFileHandler = new RemoteObjectHandler(remoteHost, m2mUser);
        final File localFile = createFile(smrsAccountName);

        assertEquals(true, iMServiceOperator.isExistingM2MUser(smrsAccountName).equals("true"));

        for (int repeatCounter = 0; repeatCounter < repeatMax; repeatCounter++) {
            LOGGER.info("copyLocalFileToRemote attemp: {}, using arguments: {} and {}", repeatCounter, localFile.getAbsolutePath(), relativePath);
            LOGGER.info("Pass: {}", remoteFileHandler.getPass());
            LOGGER.info("User info: {}", remoteFileHandler.getUser());

            didLocalToRemoteCopyWork = remoteFileHandler.copyLocalFileToRemote(localFile.getAbsolutePath(), relativePath);
            LOGGER.info("After copyLocalFileToRemote returned: {}", didLocalToRemoteCopyWork);

            if (didLocalToRemoteCopyWork) {
                break;
            }

            try {
                LOGGER.info("Sleeping for " + timeInSeconds + " seconds...");
                sleep(timeInSeconds * 1000);
            } catch (final InterruptedException e) {

                LOGGER.error("Interrupted exception while sleeping: ", e);
            }
        }

        assertEquals(true, didLocalToRemoteCopyWork);

        for (int repeatCounter = 0; repeatCounter < repeatMax; repeatCounter++) {
            LOGGER.info("copyRemoteToLocal attemp: {}, using arguments: {} and {}", repeatCounter, relativePath + TEST_FILE_NAME,
                    localFile.getAbsolutePath());

            if (remoteFileHandler.remoteFileExists(relativePath + TEST_FILE_NAME)) {
                LOGGER.info("file: {} under path: {} does not exist!", TEST_FILE_NAME, relativePath);
            }

            didRemoteToLocalCopyWork = remoteFileHandler.copyRemoteFileToLocal(relativePath + TEST_FILE_NAME, localFile.getAbsolutePath());
            LOGGER.info("After copyRemoteToLocal returned: {}", didRemoteToLocalCopyWork);

            if (didRemoteToLocalCopyWork) {
                break;
            }

            try {
                LOGGER.info("Sleeping for " + timeInSeconds + " seconds...");
                sleep(timeInSeconds * 1000);
            } catch (final InterruptedException e) {

                LOGGER.error("Interrupted exception while sleeping: ", e);
            }
        }

        assertEquals(true, didRemoteToLocalCopyWork);

        remoteFileHandler = new RemoteObjectHandler(remoteHost);

        for (int repeatCounter = 0; repeatCounter < repeatMax; repeatCounter++) {
            LOGGER.info("deleteRemoteFile attemp: {}, using arguments: {}", repeatCounter, smrsHomeDirectory + TEST_FILE_NAME);
            didDeleteWork = remoteFileHandler.deleteRemoteFile(smrsHomeDirectory + TEST_FILE_NAME);

            if (didDeleteWork) {
                break;
            }

            try {
                LOGGER.info("Sleeping for " + timeInSeconds + " seconds...");
                sleep(timeInSeconds * 1000);
            } catch (final InterruptedException e) {

                LOGGER.error("Interrupted exception while sleeping: ", e);
            }
        }

        assertEquals(true, didDeleteWork);
    }

    /**
     * @DESCRIPTION Test Case if all target groups are returned
     * @PRE IM service Running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-14211_Func_1", title = "TORF-14211_Func_1: Get All Target Groups")
    @DataDriven(name = "imservice_functionaltest_getalltargetgroups")
    @Test(groups = { "Acceptance", "RFA" })
    public void GetAllTargetGroups(@Output("expected") final String expected) {

        LOGGER.info("Get All Target Groups");
        assertEquals(expected, iMServiceOperator.getAllTargetGroups());
    }

    /**
     * @DESCRIPTION Test case to check default target group is returned
     * @PRE IM Service running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-14211_Func_2", title = "TORF-14211_Func_2: Get Default Target Group")
    @DataDriven(name = "imservice_functionaltest_getdefaulttargetgroup")
    @Test(groups = { "Acceptance", "RFA" })
    public void GetDefaultTargetGroup(@Output("expected") final String expected) {
        LOGGER.info("Get Default Target Group");
        assertEquals(expected, iMServiceOperator.getDefaultTargetGroup());
    }

    /**
     * @DESCRIPTION Test case to check if valid target groups are returned
     * @PRE IM service Running
     * @PRIORITY HIGH
     */
    @TestId(id = "TORF-14211_Func_3", title = "TORF-14211_Func_3: Validate Target Group")
    @DataDriven(name = "imservice_functionaltest_getvalidtargetgroups")
    @Test(groups = { "Acceptance", "RFA" })
    public void GetValidTargetGroup(@Input("targetGroupsToValidate") final String targetGroupsToValidate, @Output("expected") final String expected) {
        LOGGER.info("Get Valid Target group");
        assertEquals(expected, iMServiceOperator.validateTargetGroups(targetGroupsToValidate));
    }

    private File createFile(final String fileData) {

        byte[] fileContents = new byte[0];
        try {
            fileContents = fileData.getBytes("UTF-8");
        } catch (final UnsupportedEncodingException e) {
            LOGGER.error(e.toString());
            fail("Problem with file content encoding");
        }

        final File file = new File(TEST_FILE_NAME);
        try {
            final FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(fileContents);
            fileOutputStream.close();
        } catch (final Exception e) {
            LOGGER.error(e.toString());
            fail("Problem handling file operations");
        }

        return file;
    }

    private String ldapSearchUserFull(final String userName) {
        LOGGER.debug("Method ldapSearchUserFull: start, serching for user: {}", userName);
        final String dc = "dc=" + searchForDc();
        final String args = "-b \"ou=proxyagent,ou=com," + dc + ",dc=com\" cn=" + userName + " \"+\"";
        final String ldapCommandArgs = getLdapsAuthProperty() + args;
        cliOperator.writeln("ldapsearch", ldapCommandArgs);
        LOGGER.info("Executed comand: ldapsearch {}", ldapCommandArgs);
        final String output = cliOperator.getStdOut();
        LOGGER.info("Method ldapSearchUserFull: finished");
        return output;
    }

    private boolean ensureDesiredDirectoryExist(final String directoryPath) {
        boolean directoryCreated = false;
        cliOperator.writeln("cd", directoryPath);
        final String output = cliOperator.getStdOut();
        if (output.contains("No such file or directory")) {
            directoryCreated = true;
            LOGGER.info("Desired directory does not exist. Creating directory: {}", directoryPath);
            final String mkdirArgs = "-p " + directoryPath;
            cliOperator.writeln("mkdir", mkdirArgs);
            final String chmodArgs = "775 " + directoryPath;
            cliOperator.writeln("chmod", chmodArgs);
        }
        return directoryCreated;
    }

    private String ldapDeleteUserFull(final String userName) {
        LOGGER.debug("Method ldapDeleteUserFull: start, serching for user: {}", userName);
        final String ldapCommandArgs = getLdapsAuthProperty() + userName;
        cliOperator.writeln("ldapdelete", ldapCommandArgs);
        LOGGER.debug("Executed comand: ldapdelete{}", ldapCommandArgs);
        LOGGER.debug("Method ldapDeleteUserFull: finished");
        final String output = cliOperator.getStdOut();
        return output;
    }

    private String getLdapsAuthProperty() {
        final String user = "cn=Directory Manager";
        final String port = DataHandler.getAttribute("ldapsAuth.port").toString();
        final String passwordAdmin = getLdapAdminPassword();
        LOGGER.info("After get admin pass, pass is: {}", passwordAdmin);
        final String authProp = "-p " + port + " --useSSL --trustAll " + " -D \"" + user + "\" -w " + passwordAdmin + " ";
        return authProp;
    }

    private String searchForDc() {
        LOGGER.info("searchFodDc - START");
        cliOperator.writeln("getDCFromProperties");
        final String output = cliOperator.getStdOut();
        //String[] split = output.split("\\r?\\n");
        //logger.info("split[0] {} split[1] {}", split[0], split[1]);
        /* List<String> list = Arrays.asList(output.split("\n")); */
        LOGGER.info("searchForDC - output: {}", output);
        final String formatedOutput = formatOutputFromConsole(output);
        final String regExp = "(.*),ou=(.*),dc=(.*),dc=(.*)";
        final Pattern pattern = Pattern.compile(regExp);
        final Matcher matcher = pattern.matcher(formatedOutput);
        matcher.matches();
        LOGGER.info("Matcher group 3 {}", matcher.group(3));
        final String dc = matcher.group(3);
        LOGGER.info("DC found: {}", dc);
        return dc;

    }

    private String formatOutputFromConsole(final String output) {
        final String[] split = output.split("\\r?\\n");
        return split[1];
    }

    private String getLdapAdminPassword() {
        final String getAdminPassCommand = cliOperator.getCommand("getAdminPass");
        final CLICommandHelper helper = new CLICommandHelper(HostConfigurator.getMS());
        final Shell shell = helper.getShell();
        shell.writeln(getAdminPassCommand);
        final String read = shell.read();
        helper.disconnect();
        return formatOutputFromConsole(read);
    }
}
