/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * cditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.nms.security.taf.test.operators;

import java.util.*;

import javax.naming.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ericsson.cifwk.taf.data.Host;
import com.ericsson.cifwk.taf.handlers.AsRmiHandler;

public class IdentityMgmtAsRmiHandler extends AsRmiHandler {

    private static Logger log = LoggerFactory.getLogger(IdentityMgmtAsRmiHandler.class);
    private static String SNAPSHOT_NAME = "SNAPSHOT";
    private static String SNAPSHOT_PATTERN = "-" + SNAPSHOT_NAME;

    public IdentityMgmtAsRmiHandler(Host jbossNode) {
        super(jbossNode);
    }

    /**
     * Get Versions of deployed services
     *
     * @param ServiceNamePattern
     *          When local env detected, it calculates the version of service autonomously,
     *          because the service deployed may be versioned using SNAPSHOT.
     *          Otherwise parent's method is invoked
     * @return Sorted list of versions
     * @throws NamingException

     */
    @Override
    public List<String> getServiceVersion(String serviceNamePattern)
            throws NamingException {

        log.info("getServiceVersion is invoked with serviceNamePattern [{}]",
                serviceNamePattern);
        List<String> versions = super.getServiceVersion(serviceNamePattern);

        if (versions.contains(SNAPSHOT_NAME)) {
            //The returned version is SNAPSHOT because on the machine is running a temp version, not
            //official one. Only in this case the version is recalculated
            versions = new ArrayList<String>();
            log.info("Invoking local implementation");
            NamingEnumeration<Binding> list = null;
            int retryCount = 0;
            while (retryCount < 3) {
                try {
                    list = getContext().listBindings("");
                    break;
                } catch (NamingException e) {
                    log.error("Problem listing bindings: " + e.getMessage());
                    if (retryCount == 3)
                        throw e;
                }
            }
            try {
                while (list.hasMore()) {
                    String name = list.next().getName();
                    if (name.contains(serviceNamePattern)) {
                        //Check if found match contains SNAPSHOT pattern
                        boolean isSnapshot = false;
                        if (name.contains(SNAPSHOT_PATTERN)) {
                            isSnapshot = true;
                            name = name.replace(SNAPSHOT_PATTERN, "");
                            log.info("Replacing snapshot pattern [{}] with empty string, name [{}]",
                                    SNAPSHOT_PATTERN,
                                    name);
                        }
                        String targetVersion = name.substring(name.lastIndexOf('-') + 1);

                        if (isSnapshot) {
                            //Add to the calculated version the SNAPSHOT_PATTEN
                            targetVersion += SNAPSHOT_PATTERN;
                            log.info("Prepending snapshot pattern [{}], targetVersion [{}]",
                                    SNAPSHOT_PATTERN,
                                    targetVersion);
                        }

                        versions.add(targetVersion);
                    }
                }
            } catch (NamingException e) {
                log.error("Problem listing bindings: " + e);
            }
            Collections.sort(versions);
        }
        return versions;
    }
}