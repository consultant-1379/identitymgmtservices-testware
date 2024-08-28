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

import com.ericsson.nms.security.taf.test.models.IdentityManagementServicesResponse;

/**
 * Created by xadalac on 12/02/15.
 *
 * This interface specifies methods for management of Posix Attributes for users in ENM.
 */
public interface IdentityManagementServicesOperator {

    /**
     * This method delete given posix attribute for given user
     *
     * @param userName
     * @param posixAttributeGroupName
     * @return response in json format to web server with success or an error message
     */
    IdentityManagementServicesResponse removePosixAttribute(String userName, String posixAttributeGroupName);

}
