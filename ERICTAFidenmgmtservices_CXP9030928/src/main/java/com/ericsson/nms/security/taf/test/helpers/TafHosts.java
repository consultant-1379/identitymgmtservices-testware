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
package com.ericsson.nms.security.taf.test.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.data.Host;
import com.ericsson.cifwk.taf.data.exception.IncorrectHostConfigurationException;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;

/**
 * Class providing common interface to access the hosts in case of a TOR deployment.
 *
 * Reads the hosts from HostConfigurator
 *
 * TOR deployment contains the following hosts: SC1 SC2 SC1 JBOSS instance SC2 JBOSS instance
 *
 */
public class TafHosts {

    static Host parent;
    static Host sc1;
    static Host sc2;
    static Logger logger = LoggerFactory.getLogger(TafHosts.class);

    /**
     * @return SC-1 Host
     */
    public static Host getSC1() {
        return sc1;
    }

    /**
     * @return SC-2 Host
     */
    public static Host getSC2() {
        return sc2;
    }

    private static String getRealIp(final Host host) {
        final String origIp = host.getOriginalIp();
        final String ip = (null == origIp) ? host.getIp() : origIp;
        return ip;
    }

    static {
        final String deploymentType = (String) DataHandler.getAttribute("deployment.type");

        if ("multinode".equals(deploymentType)) {
            logger.info("Found multinode deplyoment in host.properties.");
        } else if ("cloud".equals(deploymentType)) {
            logger.info("Found cloud environment in host.properties.");
        } else {
            logger.info("Deployment type is unkown: " + deploymentType);
        }

        TafHosts.sc1 = HostConfigurator.getMS();
        TafHosts.sc2 = HostConfigurator.getMS();

        printHost("sc1", TafHosts.sc1);
        printHost("sc2", TafHosts.sc2);
    }

    public static void printHost(final String hostname, final Host host) {
        if (null != host) {
            String parent = null;
            final boolean notSvcNode = !host.getHostname().matches("svc[0-9]");
            try { // without this try catch Release job is failing
                if (notSvcNode) {
                    parent = host.getParentName();
                }
            } catch (final IncorrectHostConfigurationException e) {
                e.printStackTrace();
            }

            try {
                logger.info("Host: " + host.getHostname() + "\n" + "Type: " + host.getType() + "\n" + "Ip: " + host.getIp() + "\n" + "OrigIp: "
                        + host.getOriginalIp() + "\n" + "RealIp: " + getRealIp(host) + "\n" + "User: " + host.getUser() + "\n" + "Pass: "
                        + host.getPass() + "\n" + "TunnelPortOffset: " + host.getTunnelPortOffset() + "\n" + "Parent: " + parent + "\n" + "Nodes: "
                        + host.getNodes() + "\n");

            } catch (final Exception e) {
                e.printStackTrace();
            }
        } else {
            logger.error(hostname + ": Host info is null" + "\n");
        }
    }
}
