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
package com.ericsson.nms.security.taf.test.flows;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.nms.security.taf.test.teststeps.ComAAInfoTestSteps;

public class ComAaInfoTestFlow {

    @Inject
    private ComAAInfoTestSteps aaInfoTestSteps;

    public TestStepFlow comAaInfoMainFlow() {
        final TestStepFlow mainFlow = flow("mainFlow")//
                .addTestStep(annotatedMethod(aaInfoTestSteps, ComAAInfoTestSteps.SHOULD_RETURN_CORRECT_CONNECTION_DATA)).build();

        return mainFlow;
    }

}
