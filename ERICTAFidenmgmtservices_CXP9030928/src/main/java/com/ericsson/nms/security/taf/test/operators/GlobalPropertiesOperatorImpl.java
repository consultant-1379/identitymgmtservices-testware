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

import java.io.*;
import java.util.Properties;

import javax.inject.Singleton;

import com.ericsson.cifwk.taf.tools.cli.handlers.impl.RemoteObjectHandler;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;

@Singleton
public class GlobalPropertiesOperatorImpl {

    private static final String REMOTE_GLOBAL_PROPERTIES = "/ericsson/tor/data/global.properties";
    private static final String LOCAL_GLOBAL_PROPERTIES = "target/comaa_taf_global.properties";

    private Properties globalProperties;

    public String getFirstValueOfProperty(final String key) {
        final String value = getProperty(key);
        return value.split(",")[0];
    }

    public String getSecondValueOfProperty(final String key) {
        final String value = getProperty(key);
        final String[] splited = value.split(",");
        return (splited.length > 1) ? splited[1] : "";
    }

    private String getProperty(final String key) {
        loadProperties();
        return globalProperties.getProperty(key, "");
    }

    synchronized private void loadProperties() {
        if (globalProperties == null) {
            final RemoteObjectHandler remoteObjectHandler = new RemoteObjectHandler(HostConfigurator.getMS());
            remoteObjectHandler.copyRemoteFileToLocal(REMOTE_GLOBAL_PROPERTIES, LOCAL_GLOBAL_PROPERTIES);

            globalProperties = new Properties();
            try (InputStream inStream = new FileInputStream(LOCAL_GLOBAL_PROPERTIES)) {
                globalProperties.load(inStream);
            } catch (final IOException e) {
                throw new RuntimeException("Error while reading global.properties file");
            }
        }
    }

    /*
     * for unit test only
     */
    void setGlobalProperties(final Properties globalProperties) {
        this.globalProperties = globalProperties;
    }
}
