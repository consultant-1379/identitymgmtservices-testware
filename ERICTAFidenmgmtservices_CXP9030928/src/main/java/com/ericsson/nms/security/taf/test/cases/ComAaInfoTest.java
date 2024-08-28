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
package com.ericsson.nms.security.taf.test.cases;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.api.ExceptionHandler;
import com.ericsson.nms.security.taf.test.flows.ComAaInfoTestFlow;
@Deprecated
public class ComAaInfoTest extends TafTestBase {

    @Inject
    private ComAaInfoTestFlow aaInfoTestFlow;

    @TestId(id = "TORF-80737", title = "Verify that correct IPs and ports are returned")
    @Test
    public void comAaInfoTest() {

        final TestScenarioRunner scenarioRunner = runner().build();

        scenarioRunner.start(scenario().addFlow(aaInfoTestFlow.comAaInfoMainFlow()).build());

    }

}
