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

import static org.junit.Assert.*;

import java.util.Properties;

import org.junit.Before;
import org.junit.Test;

public class GlobalPropertiesOperatorImplTest {

    private static final String KEY = "any_key";
    private static final String FIRST_VALUE = "first_value";
    private static final String SECOND_VALUE = "second_value";

    private GlobalPropertiesOperatorImpl globalPropertiesOperator;
    private Properties properties;

    @Before
    public void setUp() {
        globalPropertiesOperator = new GlobalPropertiesOperatorImpl();
        properties = new Properties();
    }

    @Test
    public void shouldReturnFirstValue() {
        properties.put(KEY, FIRST_VALUE + "," + SECOND_VALUE);
        globalPropertiesOperator.setGlobalProperties(properties);

        final String valueOfProperty = globalPropertiesOperator.getFirstValueOfProperty(KEY);

        assertEquals(FIRST_VALUE, valueOfProperty);
    }

    @Test
    public void shouldReturnSecondValue() {
        properties.put(KEY, FIRST_VALUE + "," + SECOND_VALUE);
        globalPropertiesOperator.setGlobalProperties(properties);

        final String valueOfProperty = globalPropertiesOperator.getSecondValueOfProperty(KEY);

        assertEquals(SECOND_VALUE, valueOfProperty);
    }

    @Test
    public void shouldReturnEmptyFirstValueWhenPropertyEmpty() {
        properties.put(KEY, "");
        globalPropertiesOperator.setGlobalProperties(properties);

        final String valueOfProperty = globalPropertiesOperator.getSecondValueOfProperty(KEY);

        assertEquals("", valueOfProperty);
    }

    @Test
    public void shouldReturnEmptyFirstValueWhenPropertyNotExist() {
        globalPropertiesOperator.setGlobalProperties(properties);

        final String valueOfProperty = globalPropertiesOperator.getSecondValueOfProperty(KEY);

        assertEquals("", valueOfProperty);
    }

    @Test
    public void shouldReturnEmptySecondValueWhenPropertyEmpty() {
        properties.put(KEY, "");
        globalPropertiesOperator.setGlobalProperties(properties);

        final String valueOfProperty = globalPropertiesOperator.getSecondValueOfProperty(KEY);

        assertEquals("", valueOfProperty);
    }

    @Test
    public void shouldReturnEmptySecondValueWhenPropertyNotExist() {
        globalPropertiesOperator.setGlobalProperties(properties);

        final String valueOfProperty = globalPropertiesOperator.getSecondValueOfProperty(KEY);

        assertEquals("", valueOfProperty);
    }

    @Test
    public void shouldReturnEmptySecondValueWhenNoComaInProperty() {
        properties.put(KEY, FIRST_VALUE);
        globalPropertiesOperator.setGlobalProperties(properties);

        final String valueOfProperty = globalPropertiesOperator.getSecondValueOfProperty(KEY);

        assertEquals("", valueOfProperty);
    }


}
