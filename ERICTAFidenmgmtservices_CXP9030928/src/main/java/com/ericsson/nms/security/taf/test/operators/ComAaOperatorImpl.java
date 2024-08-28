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

import javax.inject.Inject;
import javax.inject.Singleton;

import com.ericsson.cifwk.taf.tools.cli.CLICommandHelper;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;
import com.ericsson.oss.itpf.security.identitymgmtservices.comaa.ConnectionData;
import com.ericsson.oss.itpf.security.identitymgmtservices.comaa.LdapAddress;

@Singleton
public class ComAaOperatorImpl implements ComAaOperator {

    private static final int EXPECTED_LDAPS_PORT = 1636;
    private static final int EXPECTED_LDAP_TLS_PORT = 1389;
    //in standalone-enm.xml: <property name="comaa_ipv6_primary_vip" value="${cm_ipv6_VIP:[::1]}"/>
    private static final String IPV6_VALUE_WHEN_NOT_CONFIGURED = "[::1]";

    @Inject
    private IMServiceApiOperator imServiceApiOperator;

    @Override
    public ConnectionData getExpectedConnectionData() {
        final String ipCMv4 = HostConfigurator.getLVSRouterCM().getIp();
        final String ipFMv4 = HostConfigurator.getLVSRouterFM().getIp();
        final String ipCMv6 = HostConfigurator.getLVSRouterCM().getIpv6();
        final String ipFMv6 = HostConfigurator.getLVSRouterFM().getIpv6();

        if (isIpV6Enabled()) {
            return new ConnectionData(new LdapAddress(ipCMv4, ipFMv4), new LdapAddress(ipCMv6, ipFMv6), EXPECTED_LDAP_TLS_PORT, EXPECTED_LDAPS_PORT);
        } else {
            return new ConnectionData(new LdapAddress(ipCMv4, ipFMv4),
                    new LdapAddress(IPV6_VALUE_WHEN_NOT_CONFIGURED, IPV6_VALUE_WHEN_NOT_CONFIGURED), EXPECTED_LDAP_TLS_PORT, EXPECTED_LDAPS_PORT);
        }
    }

    @Override
    public ConnectionData getConnectionData() {
        return imServiceApiOperator.getComAaInfo();
    }

    private boolean isIpV6Enabled() {
        final CLICommandHelper ms = new CLICommandHelper(HostConfigurator.getMS());
        ms.execute("grep svc_CM_vip_ipv6address /ericsson/tor/data/global.properties");
        return ms.getCommandExitValue() == 0;
    }
}
