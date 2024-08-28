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
package com.ericsson.nms.security.taf.test.models;

import com.ericsson.cifwk.taf.tools.http.constants.HttpStatus;
import com.ericsson.nms.security.taf.test.operators.IdentityManagementServicesOperator;

/**
 * This class is a generic for a response from methods in {@link IdentityManagementServicesOperator}.
 *
 * @param <T>
 */
public class IdentityManagementServicesResponse<T> {

    private T result;

    private HttpStatus responseCode;

    public T getResult() {
        return result;
    }

    public void setResult(final T result) {
        this.result = result;
    }

    public HttpStatus getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(final HttpStatus responseCode) {
        this.responseCode = responseCode;
    }
}
