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

import java.io.FileNotFoundException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.data.Host;
import com.ericsson.cifwk.taf.data.User;
import com.ericsson.cifwk.taf.data.UserType;
import com.ericsson.cifwk.taf.tools.cli.CLI;
import com.ericsson.cifwk.taf.tools.cli.CLICommandHelper;
import com.ericsson.cifwk.taf.tools.cli.Shell;
import com.ericsson.cifwk.taf.tools.cli.TimeoutException;
import com.ericsson.cifwk.taf.tools.cli.handlers.impl.RemoteObjectHandler;
import com.ericsson.cifwk.taf.utils.FileFinder;
import com.ericsson.nms.security.taf.test.helpers.TafHosts;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;
import com.google.inject.Singleton;

@Singleton

public class CliOperatorImpl implements CliOperator {

    private CLI cli;
    private Shell shell;
    private CLICommandHelper cmdHelper;
    Logger logger = LoggerFactory.getLogger(CliOperatorImpl.class);

    private Host secServ;
    private Host secServInternal;

    public Host getSecServInternal() {
        if (secServInternal == null) {
            secServInternal = HostConfigurator.useInternal(getSecServ1());
            secServInternal.addUser("guest", "guestp", UserType.OPER);
        }
        logger.info("secServInternal {}, ip: {}", secServInternal, secServInternal.getIp());
        return secServInternal;
    }

    @Override
    public String getCommand(final String command) {
        return DataHandler.getAttribute(cliCommandPropertyPrefix + command).toString();
    }

    @Override
    public String initializeShell(String hostname) {
        String actualHostname;
        Host host;

        if (hostname.equalsIgnoreCase("sc1") || hostname.equalsIgnoreCase("svc1")) {
            //old implementation - to be removed after switching to KVM
            host = (hostname.equalsIgnoreCase("sc1") || hostname.equalsIgnoreCase("svc1")) ? TafHosts.getSC1() : TafHosts.getSC2();

            logger.info("initializeShell: hostname=" + hostname + " host=" + host);
            actualHostname = openSession(host);
            logger.info("initializeShell: actualHostname=" + actualHostname);
            if (actualHostname == null) {
                host = (hostname.equalsIgnoreCase("sc1") || hostname.equalsIgnoreCase("svc1")) ? TafHosts.getSC2() : TafHosts.getSC1();
                hostname = host.getHostname();
                logger.info("trying to access another host: " + hostname);
                actualHostname = openSession(host);
                if (actualHostname == null) {
                    logger.error("initializeShell: unable to initialize session on either sc1 or sc2");
                } else {
                    logger.info("initializeShell: hostname to be used =" + actualHostname + " host=" + host);
                }
            }
        } else if (hostname.equalsIgnoreCase("db1")) {
            host = HostConfigurator.getDb1();

            final Host hostMS = HostConfigurator.getMS();
            cmdHelper = new CLICommandHelper(hostMS);
            final String keyFileName = HostConfigurator.getKeyFile();

            cmdHelper.newHopBuilder().hopWithKeyFile(host, keyFileName).build();

            shell = cmdHelper.getShell();
            actualHostname = host.getHostname();
        } else if (hostname.equalsIgnoreCase("secServ_1")) {

            host = getSecServ1();

            final Host hostMS = HostConfigurator.getMS();
            cmdHelper = new CLICommandHelper(hostMS);
            final String keyFileName = HostConfigurator.getKeyFile();

            final User root = new User("root", "passw0rd", UserType.APPL_ADM);
            cmdHelper.newHopBuilder().hopWithKeyFile(host, keyFileName).hop(root).build();

            shell = cmdHelper.getShell();
            actualHostname = host.getHostname();
        } else {
            host = DataHandler.getHostByName(hostname);
            logger.info("InitializeShell: hostname = " + host.getHostname() + " IP = " + host.getIp());
            actualHostname = openSession(host);
            logger.info("Shell opened on: " + actualHostname);
        }

        return actualHostname;
    }

    public Host getSecServ1() {
        if (secServ == null) {
            final CLICommandHelper ms = new CLICommandHelper(HostConfigurator.getMS());
            ms.execute("grep -w security-1-internal /etc/hosts");
            if (ms.getCommandExitValue() == 0) {
                secServ = HostConfigurator.getHost("security_1");
            } else {
                secServ = HostConfigurator.getSecServiceUnit0();
            }
        }
        logger.info("secServ {}, ip: {}", secServ, secServ.getIp());
        return secServ;
    }

    private String openSession(final Host host) {
        if (host == null) {
            return null;
        }
        final String hostName = host.getHostname();
        cli = new CLI(host);
        if (shell == null) {
            logger.info("Open new session on host: " + hostName);
            try {
                shell = cli.openShell();
            } catch (final Exception e) {
                logger.error(":::::::::::::::::::::::::Exception caught:" + e.getMessage());
                return null;
            }
            logger.info("Creating new shell instance on host: " + hostName);
        }
        return hostName;
    }

    @Override
    public void writeln(final String command, final String args) {
        final String cmd = getCommand(command);
        logger.debug("Writing " + cmd + " " + args + " to standard input");
        shell.writeln(cmd + " " + args);
    }

    @Override
    public void writeln(final String command) {
        final String cmd = getCommand(command);
        logger.debug("Writing " + cmd + " to standard input");
        shell.writeln(cmd);
    }

    @Override
    public int getExitValue() {
        final int exitValue = shell.getExitValue();
        logger.debug("Getting exit value from shell, exit value is: " + exitValue);
        return exitValue;
    }

    @Override
    public String expect(final String expectedText) throws TimeoutException {
        logger.debug("Expected return is " + expectedText);
        final String found = shell.expect(expectedText);
        logger.debug("Found string <" + found + ">");
        return found;
    }

    @Override
    public void expectClose(final int timeout) throws TimeoutException {
        shell.expectClose(timeout);
    }

    @Override
    public boolean isClosed() throws TimeoutException {
        return shell.isClosed();
    }

    @Override
    public String checkForNullError(String error) {
        if (error == null) {
            error = "";
            return error;
        }
        return error;
    }

    @Override
    public String getStdOut() {
        final String result = shell.read();
        logger.debug("Standard out: " + result);
        return result;
    }

    @Override
    public void disconnect() {
        logger.info("Disconnecting from shell");
        shell.disconnect();
        shell = null;
    }

    @Override
    public void sendFileRemotely(final String hostname, final String fileName, final String fileServerLocation) throws FileNotFoundException {
        final Host host = (hostname.equalsIgnoreCase("sc1") || hostname.equalsIgnoreCase("svc1")) ? TafHosts.getSC1() : TafHosts.getSC2();

        final RemoteObjectHandler remoteObjectHandler = new RemoteObjectHandler(host);

        final List<String> fileLocation = FileFinder.findFile(fileName);
        final String remoteFileLocation = fileServerLocation; //unix address
        remoteObjectHandler.copyLocalFileToRemote(fileLocation.get(0), remoteFileLocation);
        logger.debug("Copying " + fileName + " to " + remoteFileLocation + " on remote host " + host.getHostname() + ".");

    }

    @Override
    public void deleteRemoteFile(final String hostname, final String fileName, final String fileServerLocation) throws FileNotFoundException {
        final Host host = (hostname.equalsIgnoreCase("sc1") || hostname.equalsIgnoreCase("svc1")) ? TafHosts.getSC1() : TafHosts.getSC2();

        final RemoteObjectHandler remoteObjectHandler = new RemoteObjectHandler(host);
        final String remoteFileLocation = fileServerLocation;
        remoteObjectHandler.deleteRemoteFile(remoteFileLocation + fileName);
        logger.debug("deleting " + fileName + " at location " + remoteFileLocation + " on remote host");
    }

    @Override
    public void scriptInput(final String message) {
        logger.info("Writing " + message + " to standard in");
        shell.writeln(message);
    }

    @Override
    public Shell executeCommand(final String... commands) {
        logger.info("Executing command(s) " + commands);
        return cli.executeCommand(commands);

    }
}
