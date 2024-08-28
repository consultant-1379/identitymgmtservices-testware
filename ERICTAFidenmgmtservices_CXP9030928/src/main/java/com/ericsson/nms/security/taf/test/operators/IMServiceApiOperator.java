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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.ejb.EJBException;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.data.Host;
import com.ericsson.oss.itpf.security.identitymgmtservices.IdentityManagementService;
import com.ericsson.oss.itpf.security.identitymgmtservices.IdentityManagementServiceException;
import com.ericsson.oss.itpf.security.identitymgmtservices.M2MUser;
import com.ericsson.oss.itpf.security.identitymgmtservices.ProxyAgentAccountData;
import com.ericsson.oss.itpf.security.identitymgmtservices.comaa.ComAAInfo;
import com.ericsson.oss.itpf.security.identitymgmtservices.comaa.ConnectionData;
import javax.naming.NamingException;

public class IMServiceApiOperator implements IMServiceOperator {

    Logger logger = LoggerFactory.getLogger(getClass());

    public static final String SERVICE_NAME = "identitymgmtservices";

    public static final String JNDI_VERSION_PATTERN = "XXVERSIONXX";

    public static final String IMSERVICE_JNDI_PROPERTY = "imservice.jndi";

    public static final String COMAAINFO_JNDI_PROPERTY = "comaainfo.jndi";

    public static final String UNKNOWN_EXCEPTION_MSG = "UNKNOWN_EXCEPTION";

    @Inject
    private CliOperatorImpl cliOperator;

    @Override
    public String createProxyAgent() {
        logger.debug("IMServiceApiOperator: createProxyUser start");

        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        ProxyAgentAccountData user = null;
        String DN = null;
        try {
            user = ims.createProxyAgentAccount();
            DN = user.getUserDN();
            logger.debug("IMServiceApiOperator: created proxy user: {}", DN);
        } catch (final IdentityManagementServiceException e) {
            final String errMsg = getErrorMessage(e);
            logger.error("IMServiceApiOperator: createProxyUser: IdentityManagementServiceException occur {}", errMsg);
            return errMsg + "result:false";
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.error("IMServiceApiOperator: createProxyUser: {} occur", errMsg);
                return errMsg + "result:false";
            } else {
                logger.error("IMServiceApiOperator: createProxyUser: unknow exception occur {}", errMsg);
                return errMsg + "result:false";
            }
        }
        logger.debug("IMServiceApiOperator: finished");
        return DN;
    }

    @Override
    public String deleteProxyAgent(final String DN) {
        logger.debug("IMServiceApiOperator: deleteProxyAgent: {}", DN);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        boolean isDeleted;
        try {
            isDeleted = ims.deleteProxyAgentAccount(DN);
            if (!isDeleted) {
                logger.debug("IMServiceApiOperator: deleteProxyAgent: {} User doesnot exists", DN);
                return "false";
            }
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.error("IMServiceApiOperator: deleteProxyUser: {} occur", errMsg);
                return errMsg + "result:false";
            } else {
                logger.error("IMServiceApiOperator: deleteProxyUser: unknow exception occur {}", errMsg);
                return errMsg + "result:false";
            }
        }
        return "true";
    }

    /*
     * remove test user if it exists
     */
    @Override
    public String cleanUp(final String user) {
        logger.info("Check " + user);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        try {
            if (ims.isExistingM2MUser(user)) {
                logger.info("Deleting " + user);
                ims.deleteM2MUser(user);
            }
        } catch (final IdentityManagementServiceException imse) {
            logger.error("caught IdentityManagementServiceException");
            logger.error(imse.getMessage());

            return "SUCCESS";
        }
        return "SUCCESS";
    }

    private String getIdentityManagementServiceVersion(final IdentityMgmtAsRmiHandler asRmiHandler)
                                throws NamingException,  IllegalStateException {
        List<String> versionList = asRmiHandler.getServiceVersion(SERVICE_NAME);
        if (versionList == null || versionList.isEmpty()) {
            String errorMessage = String.format("IMServiceApiOperator: Versions for [%s] is null or empty", SERVICE_NAME);
            logger.error(errorMessage);
            throw new IllegalStateException(errorMessage);
        } else if (versionList.size() > 1) {
            String errorMessage = String.format("IMServiceApiOperator: Too many versions found [%s]"
                    + " for [%s]", versionList.size(), SERVICE_NAME);
            logger.error(errorMessage);
            throw new IllegalStateException(errorMessage);
        } else {
            logger.info("IMServiceApiOperator: Found IdentityManagementService version: [{}] for service [{}] on host", versionList.get(0), SERVICE_NAME);
        }
        return versionList.get(0);
    }

    private Object locateServiceEjb(final String jndiProperty) {

        logger.info("IMServiceApiOperator: Executing command \"locateServiceEjb\": ");
        final Host host = cliOperator.getSecServInternal();
        final IdentityMgmtAsRmiHandler asRmiHandler = new IdentityMgmtAsRmiHandler(host);
        String jndiString = (String) DataHandler.getAttribute(jndiProperty);
        logger.info("jndiString:" + jndiString);
        try {
            String version = getIdentityManagementServiceVersion(asRmiHandler);
            String result = jndiString.replaceAll(JNDI_VERSION_PATTERN, version);
            logger.info("replaceVersionForJndiLookup - jndiString [{}], patternToBeReplaced [{}], valueToReplace [{}], result [{}]",
                    jndiString,
                    JNDI_VERSION_PATTERN,
                    version,
                    result);
            jndiString = result;

            return asRmiHandler.getServiceViaJndiLookup(String.format(jndiString, version));
        } catch (final Exception error) {
            throw new IllegalStateException("IMServiceApiOperator: Failed to locate EJB on host [" + host.getHostname() + "]", error);
        }

    }

    public ConnectionData getComAaInfo() {
        logger.info("IMServiceApiOperator: getComAaInfo");
        final ComAAInfo comAAInfo = (ComAAInfo) locateServiceEjb(COMAAINFO_JNDI_PROPERTY);
        final ConnectionData connectionData = comAAInfo.getConnectionData();
        logger.info("connectionData: {}", connectionData);
        return connectionData;
    }

    @Override
    public String createM2MUser(final String userName, final String groupName, final String homeDir, final String validDays) {
        logger.info("IMServiceApiOperator: createM2MUser: " + userName + " " + groupName + " " + homeDir + " " + validDays);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        M2MUser user = null;
        String name = null;
        try {
            user = ims.createM2MUser(userName, groupName, homeDir, Integer.parseInt(validDays));
            name = user.getUserName();
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator: createM2MUser: " + userName + " " + groupName + " " + homeDir + " " + validDays + " " + errMsg);
                return errMsg;
            } else {
                logger.error("IMServiceApiOperator: createM2MUser: " + userName + " " + groupName + " " + homeDir + " " + validDays + " " + errMsg);
                return errMsg;
            }
        }
        logger.info("return SUCCESS");
        return name;
    }

    @Override
    public String deleteM2MUser(final String userName) {
        logger.info("IMServiceApiOperator: deleteM2MUser: " + userName);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        boolean isDeleted;
        try {
            isDeleted = ims.deleteM2MUser(userName);
            if (!isDeleted) {
                logger.info("IMServiceApiOperator: deleteM2MUser: " + userName + " User doesnot exists ");
                return "false";
            }
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator:deleteM2MUser" + userName + " " + errMsg);
                return "false";
            } else {
                logger.error("IMServiceApiOperator:deleteM2MUser" + userName + " " + errMsg);
                return errMsg;
            }
        }
        return "true";
    }

    @Override
    public String getM2MUser(final String userName) {
        logger.info("IMServiceApiOperator: getM2MUser: " + userName);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        M2MUser user = null;
        String name = null;
        try {
            user = ims.getM2MUser(userName);
            name = user.getUserName();
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator: getM2MUser: " + userName + " " + errMsg);
                return errMsg;
            } else {
                logger.error("IMServiceApiOperator: getM2MUser: " + userName + " " + errMsg);
                return errMsg;
            }
        }
        logger.info("return SUCCESS");
        return name;
    }

    @Override
    public String isExistingM2MUser(final String userName) {
        logger.info("IMServiceApiOperator: isExistingM2MUser: " + userName);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        boolean exists;
        try {
            exists = ims.isExistingM2MUser(userName);
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator:isExistingM2MUser " + userName + " " + errMsg);
                return "false";
            } else {
                logger.error("IMServiceApiOperator:isExistingM2MUser " + userName + " " + errMsg);
                return "false";
            }
        }
        if (exists) {
            return "true";
        }
        return "false";
    }

    @Override
    public String getM2MPassword(final String userName) {
        logger.info("IMServiceApiOperator: getM2MPassword: " + userName);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        char[] userPassword = null;
        try {
            userPassword = ims.getM2MPassword(userName);
            if (userPassword == null) {
                logger.info("IMServiceApiOperator: getM2MPassword: " + userName + ", password is null. ");
                return "FAIL";
            }
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator: getM2MPassword: " + userName + " " + errMsg);
                return errMsg;
            } else {
                logger.error("IMServiceApiOperator: getM2MPassword: " + userName + " " + errMsg);
                return errMsg;
            }

        }
        logger.info("return SUCCESS");
        return "SUCCESS";
    }

    @Override
    public char[] getM2MPasswordAsCharArray(final String userName) {
        logger.info("IMServiceApiOperator: getM2MPassword: " + userName);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        char[] userPassword = null;
        try {
            userPassword = ims.getM2MPassword(userName);
            if (userPassword == null) {
                logger.info("IMServiceApiOperator: getM2MPassword: " + userName + ", password is null. ");
                throw new IdentityManagementServiceException("IMServiceApiOperator: getM2MPassword: " + userName + ", password is null. ");
            }
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator: getM2MPassword: " + userName + " " + errMsg);
                return null;
            } else {
                logger.error("IMServiceApiOperator: getM2MPassword: " + userName + " " + errMsg);
                return null;
            }

        }
        logger.info("return SUCCESS");
        return userPassword;
    }

    @Override
    public String updateM2MPassword(final String userName) {
        logger.info("IMServiceApiOperator: updateM2MPassword: " + userName);
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        char[] userPassword = null;
        try {
            userPassword = ims.updateM2MPassword(userName);
            if (userPassword == null) {
                logger.info("IMServiceApiOperator: updateM2MPassword: " + userName + ", password is null. ");
                return "FAIL";
            }
            logger.info("IMServiceApiOperator: updateM2MPassword: " + userName + ", password is: )" + new String(userPassword));
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator: updateM2MPassword: " + userName + " " + errMsg);
                return errMsg;
            } else {
                logger.error("IMServiceApiOperator: updateM2MPassword: " + userName + " " + errMsg);
                return errMsg;
            }

        }
        logger.info("return SUCCESS");
        return "SUCCESS";
    }

    @Override
    public String getAllTargetGroups() {
        logger.info("IMServiceApiOperator:getAllTargetGroups");
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        List<String> alltargetGrouplist;
        try {
            alltargetGrouplist = ims.getAllTargetGroups();
            if (alltargetGrouplist.size() < 1) {
                logger.info("IMServiceApiOperator:getAllTargetGroups: " + "Error retrieving target groups ");
                return "FAIL";
            }
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator:getAllTargetGroups " + " " + errMsg);
                return errMsg;
            } else {
                logger.error("IMServiceApiOperator:getAllTargetGroups " + " " + errMsg);
                return errMsg;
            }

        }
        return "SUCCESS";
    }

    @Override
    public String getDefaultTargetGroup() {
        logger.info("IMServiceApiOperator:getDefaultTargetGroups");
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        String result = null;
        try {
            result = ims.getDefaultTargetGroup();
            if (result.length() < 0) {
                logger.info("IMServiceApiOperator:getDefaultTargetGroups: " + "Error retriving default target groups ");
                return "FAIL";
            }
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator:getDefaultTargetGroups " + " " + errMsg);
                return errMsg;
            } else {
                logger.error("IMServiceApiOperator:getDefaultTargetGroups " + " " + errMsg);
                return errMsg;
            }

        }
        return "SUCCESS";
    }

    @Override
    public String validateTargetGroups(final String targetGroupsToValidate) {
        logger.info("IMServiceApiOperator:validateTargetGroups");
        final IdentityManagementService ims = (IdentityManagementService) locateServiceEjb(IMSERVICE_JNDI_PROPERTY);
        final List<String> inputtargetgroups = new ArrayList<String>(Arrays.asList(targetGroupsToValidate.split(" ")));
        List<String> checkTargetGroupList = new ArrayList<String>();
        try {
            checkTargetGroupList = ims.validateTargetGroups(inputtargetgroups);
            // values returned are invalid target groups
            if (checkTargetGroupList.size() == 3) {
                final String listOfGroups = checkTargetGroupList.get(0) + " " + checkTargetGroupList.get(1) + " " + checkTargetGroupList.get(2);
                logger.info("IMServiceApiOperator:validateTargetGroups: " + listOfGroups);
                return listOfGroups;
            } else if (checkTargetGroupList.size() == 2) {
                final String listOfGroups = checkTargetGroupList.get(0) + " " + checkTargetGroupList.get(1);
                logger.info("IMServiceApiOperator:validateTargetGroups: " + listOfGroups);
                return listOfGroups;
            } else if (checkTargetGroupList.size() == 1) {
                final String listOfGroups = checkTargetGroupList.get(0);
                logger.info("IMServiceApiOperator:validateTargetGroups: " + listOfGroups);
                return listOfGroups;
            } else {
                logger.info("IMServiceApiOperator:validateTargetGroups: " + "NE_ACCESS");
            }
        } catch (final Exception imse) {
            final String errMsg = getErrorMessage(imse);
            if (!UNKNOWN_EXCEPTION_MSG.equals(errMsg)) {
                logger.info("IMServiceApiOperator:validateTargetGroups " + " " + errMsg);
                return errMsg;
            } else {
                logger.error("IMServiceApiOperator:validateTargetGroups " + " " + errMsg);
                return errMsg;
            }

        }
        return "NE_ACCESS";
    }

    private String getErrorMessage(final Exception e) {

        Throwable t = e;

        final StringWriter sw = new StringWriter();
        sw.append("Exception occurs:\n");
        t.printStackTrace(new PrintWriter(sw));

        while (t.getCause() != null) {
            t = t.getCause();
            sw.append("One more exception occurs:\n");
            t.printStackTrace(new PrintWriter(sw));
        }

        logger.info(sw.toString());

        IdentityManagementServiceException ee = null;
        if (e instanceof IdentityManagementServiceException) {
            logger.info("Exception occurs - instance of IdentityManagementServiceException");
            ee = (IdentityManagementServiceException) e;
            logger.info(ee.getMessage());
            logger.info(ee.getCause().getMessage());
        } else if (e instanceof EJBException) {
            logger.info("Exception occurs - instance of EJBException");
            logger.info(e.getMessage());
            logger.info(e.getCause().getMessage());
            if (e.getCause() instanceof IdentityManagementServiceException) {
                ee = (IdentityManagementServiceException) e.getCause();
                logger.info(ee.getMessage());
            } else {
                logger.info(e.getMessage());
                logger.info(e.getCause().getMessage());
                return UNKNOWN_EXCEPTION_MSG;
            }
        } else {
            logger.info("Exception occurs - unknknow type");
            logger.info(e.getMessage());
            logger.info(e.getCause().getMessage());
            return UNKNOWN_EXCEPTION_MSG;

        }
        if (ee.getError() == IdentityManagementServiceException.Error.NO_SUCH_ATTRIBUTE) {
            return "NO_SUCH_ATTRIBUTE";
        }
        if (ee.getError() == IdentityManagementServiceException.Error.INVALID_CREDENTIALS) {
            return "INVALID_CREDENTIALS";
        }
        if (ee.getError() == IdentityManagementServiceException.Error.ENTRY_NOT_FOUND) {
            return "NO_SUCH_ENTRY";
        }
        if (ee.getError() == IdentityManagementServiceException.Error.ENTRY_ALREADY_EXISTS) {
            return "ENTRY_ALREADY_EXISTS";
        }
        if (ee.getError() == IdentityManagementServiceException.Error.ATTR_OR_VALUE_ALREADY_EXISTS) {
            return "ATTR_OR_VALUE_ALREADY_EXISTS";
        }
        if (ee.getError() == IdentityManagementServiceException.Error.DATA_STORE_CONNECTION_FAILURE) {
            return "CONNECTION_FAILED";
        }
        if (ee.getError() == IdentityManagementServiceException.Error.UNEXPECTED_ERROR) {
            return "UNEXPECTED_ERROR";
        }

        return UNKNOWN_EXCEPTION_MSG;
    }

}
