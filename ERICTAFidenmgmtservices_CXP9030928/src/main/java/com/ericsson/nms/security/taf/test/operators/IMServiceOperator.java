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

public interface IMServiceOperator {

    /*
     * remove test user if it exists
     */
    String cleanUp(String user);

    /*
     * operations are performed on host
     */
    String createM2MUser(String userName, String groupName, String homeDir, String validDays);

    String deleteM2MUser(String userName);

    String getM2MUser(String userName);

    String isExistingM2MUser(String userName);

    String getM2MPassword(String userName);

    char[] getM2MPasswordAsCharArray(String userName);

    String updateM2MPassword(String userName);

    String getAllTargetGroups();

    String getDefaultTargetGroup();

    String validateTargetGroups(String targetGroupsToValidate);

    String createProxyAgent();

    String deleteProxyAgent(String DN);
}
