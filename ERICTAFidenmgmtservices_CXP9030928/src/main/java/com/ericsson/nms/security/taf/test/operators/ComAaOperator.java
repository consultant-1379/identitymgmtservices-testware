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
package com.ericsson.nms.security.taf.test.operators;

import com.ericsson.oss.itpf.security.identitymgmtservices.comaa.ConnectionData;
@Deprecated
public interface ComAaOperator {

    ConnectionData getConnectionData();

    ConnectionData getExpectedConnectionData();

}
