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

import java.io.File;

/**
 * Created by emaulag on 1/4/22.
 */
public class identityMgmtServiceRestConstants {

        public static final String TEST_DATA_SOURCE = "testDataSource";
        public static final String path = "data" + File.separator + "REST";
        public static final String CLEAN_UP_M2M_USER_CSV = path + File.separator + "M2M_Users_CleanUp.csv";
        public static final String DELETE_M2M_USER_CSV = path + File.separator + "Delete_M2M_Users.csv";
        public static final String CREATE_M2M_USER_CSV = path + File.separator + "Create_M2M_Users.csv";
        public static final String CHECK_M2M_USER_CSV = path + File.separator + "Check_M2M_Users_Exists.csv";
        public static final String GET_M2M_USER_CSV = path + File.separator + "Get_M2M_Users.csv";
        public static final String GET_UPDATE_M2M_USER_PASSWORD_CSV = path + File.separator + "Get_Update_M2M_Users_Password.csv";
        public static final String CREATE_REMOVE_PROXY_ACCOUNT_CSV = path + File.separator + "Create_Delete_Proxy_Agent.csv";
        public static final String IDENTITY_MGMT_SERVICE_USER_CSV = path + File.separator + "IdentityMgmtServiceTest_User_To_Create.csv";
        public static final String COMAA_INFO_USER_CSV = path + File.separator + "ComAA_INFO_User_To_Create.csv";
        public static final String COMAA_TEST_USER_ROLE_CSV = path + File.separator + "ComAA_Info_Role_To_Create.csv";
        public static final String CHECK_COM_USER_CSV = path + File.separator + "Check_COM_USER.csv";
        public static final String FUNCTIONAL_TEST_USER_ROLE_CSV = path + File.separator + "Role_To_Create.csv";
        public static final String USER_CANNOT_ACCESS_TO_REST_API_CSV = path + File.separator + "User_Cannot_Access_To_REST_API.csv";

        public static final String TEST_DATA_SOURCE_CSV = "data" + File.separator + "testDataSource.csv";
}
