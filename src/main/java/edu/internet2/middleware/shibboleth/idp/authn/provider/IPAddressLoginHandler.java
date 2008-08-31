/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.authn.provider;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.BitSet;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;

/**
 * IP Address authentication handler.
 * 
 * This "authenticates" a user based on their IP address. It operates in either default deny or default allow mode, and
 * evaluates a given request against a list of blocked or permitted IPs. It supports both IPv4 and IPv6.
 * 
 * If an Authentication Context Class or DeclRef URI is not specified, it will default to
 * "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol".
 */
public class IPAddressLoginHandler extends AbstractLoginHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(IPAddressLoginHandler.class);

    /** The URI of the AuthnContextDeclRef or the AuthnContextClass. */
    private String authnMethodURI = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol";

    /** The username to use for IP-address "authenticated" users. */
    private String username;

    /** Are the IPs in ipList a permitted list or a deny list. */
    private boolean defaultDeny;

    /** The list of denied or permitted IPs. */
    private List<IPEntry> ipList;

    /**
     * Set the permitted IP addresses.
     * 
     * If <code>defaultDeny</code> is <code>true</code> then only the IP addresses in <code>ipList</code> will be
     * "authenticated." If <code>defaultDeny</code> is <code>false</code>, then all IP addresses except those in
     * <code>ipList</code> will be authenticated.
     * 
     * @param entries A list of IP addresses (with CIDR masks).
     * @param defaultDeny Does <code>ipList</code> contain a deny or permit list.
     */
    public void setEntries(final List<String> entries, boolean defaultDeny) {

        this.defaultDeny = defaultDeny;
        ipList = new CopyOnWriteArrayList<IPEntry>();

        for (String addr : entries) {
            try {
                ipList.add(new edu.internet2.middleware.shibboleth.idp.authn.provider.IPAddressLoginHandler.IPEntry(
                        addr));
            } catch (UnknownHostException ex) {
                log.error("IPAddressHandler: Error parsing IP entry \"" + addr + "\". Ignoring.");
            }
        }
    }

    /** {@inheritDoc} */
    public boolean supportsPassive() {
        return true;
    }

    /** {@inheritDoc} */
    public boolean supportsForceAuthentication() {
        return true;
    }

    /**
     * Get the username for all IP-address authenticated users.
     * 
     * @return The username for IP-address authenticated users.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Set the username to use for all IP-address authenticated users.
     * 
     * @param name The username for IP-address authenticated users.
     */
    public void setUsername(String name) {
        username = name;
    }

    /** {@inheritDoc} */
    public void login(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {

        if (defaultDeny) {
            handleDefaultDeny(httpRequest, httpResponse);
        } else {
            handleDefaultAllow(httpRequest, httpResponse);
        }

        AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
    }

    protected void handleDefaultDeny(HttpServletRequest request, HttpServletResponse response) {

        boolean ipAllowed = searchIpList(request);

        if (ipAllowed) {
            log.debug("Authenticated user by IP address");
            request.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, username);
        }
    }

    protected void handleDefaultAllow(HttpServletRequest request, HttpServletResponse response) {

        boolean ipDenied = searchIpList(request);

        if (!ipDenied) {
            log.debug("Authenticated user by IP address");
            request.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, username);
        }
    }

    /**
     * Search the list of InetAddresses for the client's address.
     * 
     * @param request The ServletReqeust
     * 
     * @return <code>true</code> if the client's address is in <code>ipList</code>
     */
    private boolean searchIpList(ServletRequest request) {

        boolean found = false;

        try {
            InetAddress addr = InetAddress.getByName(request.getRemoteAddr());
            BitSet addrbits = byteArrayToBitSet(addr.getAddress());

            for (IPEntry entry : ipList) {

                BitSet netaddr = entry.getNetworkAddress();
                BitSet netmask = entry.getNetmask();

                addrbits.and(netmask);
                if (addrbits.equals(netaddr)) {
                    found = true;
                    break;
                }
            }

        } catch (UnknownHostException ex) {
            log.error("Error resolving hostname.", ex);
            return false;
        }

        return found;
    }

    /**
     * Converts a byte array to a BitSet.
     * 
     * The supplied byte array is assumed to have the most signifigant bit in element 0.
     * 
     * @param bytes the byte array with most signifigant bit in element 0.
     * 
     * @return the BitSet
     */
    protected BitSet byteArrayToBitSet(final byte[] bytes) {

        BitSet bits = new BitSet();

        for (int i = 0; i < bytes.length * 8; i++) {
            if ((bytes[bytes.length - i / 8 - 1] & (1 << (i % 8))) > 0) {
                bits.set(i);
            }
        }

        return bits;
    }

    /**
     * Encapsulates a network address and a netmask on ipList.
     */
    protected class IPEntry {

        /** The network address. */
        private final BitSet networkAddress;

        /** The netmask. */
        private final BitSet netmask;

        /**
         * Construct a new IPEntry given a network address in CIDR format.
         * 
         * @param entry A CIDR-formatted network address/netmask
         * 
         * @throws UnknownHostException If entry is malformed.
         */
        public IPEntry(String entry) throws UnknownHostException {

            // quick sanity checks
            if (entry == null || entry.length() == 0) {
                throw new UnknownHostException("entry is null.");
            }

            int cidrOffset = entry.indexOf("/");
            if (cidrOffset == -1) {
                log.error("Invalid entry \"" + entry + "\" -- it lacks a netmask component.");
                throw new UnknownHostException("entry lacks a netmask component.");
            }

            // ensure that only one "/" is present.
            if (entry.indexOf("/", cidrOffset + 1) != -1) {
                log.error("Invalid entry \"" + entry + "\" -- too many \"/\" present.");
                throw new UnknownHostException("entry has too many netmask components.");
            }

            String networkString = entry.substring(0, cidrOffset);
            String netmaskString = entry.substring(cidrOffset + 1, entry.length());

            InetAddress tempAddr = InetAddress.getByName(networkString);
            networkAddress = byteArrayToBitSet(tempAddr.getAddress());

            int masklen = Integer.parseInt(netmaskString);
            int addrlen = networkAddress.length();

            // ensure that the netmask isn't too large
            if ((tempAddr instanceof Inet4Address) && (masklen > 32)) {
                throw new UnknownHostException("Netmask is too large for an IPv4 address: " + masklen);
            } else if ((tempAddr instanceof Inet6Address) && masklen > 128) {
                throw new UnknownHostException("Netmask is too large for an IPv6 address: " + masklen);
            }

            netmask = new BitSet(addrlen);
            netmask.set(addrlen - masklen, addrlen, true);
        }

        /**
         * Get the network address.
         * 
         * @return the network address.
         */
        public BitSet getNetworkAddress() {
            return networkAddress;
        }

        /**
         * Get the netmask.
         * 
         * @return the netmask.
         */
        public BitSet getNetmask() {
            return netmask;
        }
    }
}