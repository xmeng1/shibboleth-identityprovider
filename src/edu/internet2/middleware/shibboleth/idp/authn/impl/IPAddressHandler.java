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

package edu.internet2.middleware.shibboleth.idp.authn.impl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.BitSet;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletRequest;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import java.net.Inet4Address;
import java.net.Inet6Address;
import javax.servlet.ServletException;

import org.apache.log4j.Logger;

import org.joda.time.DateTime;

/**
 * IP Address authentication handler.
 *
 * This "authenticates" a user based on their IP address. It operates in either
 * default deny or default allow mode, and evaluates a given request against a
 * list of blocked or permitted IPs. It supports both IPv4 and IPv6.
 */
public class IPAddressHandler implements AuthenticationHandler {
    
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
         * @param entry
         *            A CIDR-formatted network address/netmask
         *
         * @throws UnknownHostException
         *             If entry is malformed.
         */
        public IPEntry(String entry) throws UnknownHostException {
            
            // quick sanity checks
            if (entry == null || entry.length() == 0) {
                throw new UnknownHostException("entry is null.");
            }
            
            int cidrOffset = entry.indexOf("/");
            if (cidrOffset == -1) {
                log.error("IPAddressHandler: invalid entry \"" + entry
                        + "\" -- it lacks a netmask component.");
                throw new UnknownHostException(
                        "entry lacks a netmask component.");
            }
            
            // ensure that only one "/" is present.
            if (entry.indexOf("/", cidrOffset + 1) != -1) {
                log.error("IPAddressHandler: invalid entry \"" + entry
                        + "\" -- too many \"/\" present.");
                throw new UnknownHostException(
                        "entry has too many netmask components.");
            }
            
            String networkString = entry.substring(0, cidrOffset);
            String netmaskString = entry.substring(cidrOffset + 1, entry
                    .length());
            
            InetAddress tempAddr = InetAddress.getByName(networkString);
            networkAddress = byteArrayToBitSet(tempAddr.getAddress());
            
            int masklen = Integer.parseInt(netmaskString);
            int addrlen = networkAddress.length();
            
            // ensure that the netmask isn't too large
            if ((tempAddr instanceof Inet4Address) && (masklen > 32)) {
                throw new UnknownHostException(
                        "IPAddressHandler: Netmask is too large for an IPv4 address: "
                        + masklen);
            } else if ((tempAddr instanceof Inet6Address) && masklen > 128) {
                throw new UnknownHostException(
                        "IPAddressHandler: Netmask is too large for an IPv6 address: "
                        + masklen);
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
    
    private static final Logger log = Logger.getLogger(IPAddressHandler.class);
    
    /** the URI of the AuthnContextDeclRef or the AuthnContextClass */
    private String authnMethodURI;
    
    /** Are the IPs in ipList a permitted list or a deny list */
    private boolean defaultDeny;
    
    /** The list of denied or permitted IPs */
    private List<IPEntry> ipList;
    
    /** Creates a new instance of IPAddressHandler */
    public IPAddressHandler() {
    }
    
    /**
     * Set the permitted IP addresses.
     *
     * If <code>defaultDeny</code> is <code>true</code> then only the IP
     * addresses in <code>ipList</code> will be "authenticated." If
     * <code>defaultDeny</code> is <code>false</code>, then all IP
     * addresses except those in <code>ipList</code> will be authenticated.
     *
     * @param entries
     *            A list of IP addresses (with CIDR masks).
     * @param defaultDeny
     *            Does <code>ipList</code> contain a deny or permit list.
     */
    public void setEntries(final List<String> entries, boolean defaultDeny) {
        
        this.defaultDeny = defaultDeny;
        ipList = new CopyOnWriteArrayList<IPEntry>();
        
        for (String addr : entries) {
            try {
                ipList
                        .add(new edu.internet2.middleware.shibboleth.idp.authn.impl.IPAddressHandler.IPEntry(
                        addr));
            } catch (UnknownHostException ex) {
                log.error("IPAddressHandler: Error parsing entry \"" + addr
                        + "\". Ignoring.");
            }
        }
    }
    
    /** @{inheritDoc} */
    public boolean supportsPassive() {
        return true;
    }
    
    /** {@inheritDoc} */
    public boolean supportsForceAuthentication() {
        return true;
    }
    
    /** {@inheritDoc} */
    public void logout(final HttpServletRequest request,
            final HttpServletResponse response, final String principal) {
        
        // RequestDispatcher dispatcher = request
        //		.getRequestDispatcher(returnLocation);
        // dispatcher.forward(request, response);
    }
    
    /** {@inheritDoc} */
    public void login(final HttpServletRequest request,
            final HttpServletResponse response, final LoginContext loginCtx) {
        
        loginCtx.setAuthenticationAttempted();
        loginCtx.setAuthenticationInstant(new DateTime());
        
        if (defaultDeny) {
            handleDefaultDeny(request, response, loginCtx);
        } else {
            handleDefaultAllow(request, response, loginCtx);
        }
        
        // return control back to the AuthNManager.
        try {
            RequestDispatcher dispatcher =
                    request.getRequestDispatcher(loginCtx.getAuthenticationManagerURL());
            dispatcher.forward(request, response);
        } catch (ServletException ex) {
            log.error("IPAddressHandler: Error returning control to AuthnManager.", ex);
        } catch (IOException ex) {
            log.error("IPAddressHandler: Error returning control to AuthnManager.", ex);
        }
    }
    
    protected void handleDefaultDeny(HttpServletRequest request,
            HttpServletResponse response, LoginContext loginCtx) {
        
        boolean ipAllowed = searchIpList(request);
        
        if (ipAllowed) {
            loginCtx.setAuthenticationOK(true);
        } else {
            loginCtx.setAuthenticationOK(false);
            loginCtx
                    .setAuthenticationFailureMessage("User's IP is not in the permitted list.");
        }
    }
    
    protected void handleDefaultAllow(HttpServletRequest request,
            HttpServletResponse response, LoginContext loginCtx) {
        
        boolean ipDenied = searchIpList(request);
        
        if (ipDenied) {
            loginCtx.setAuthenticationOK(false);
            loginCtx
                    .setAuthenticationFailureMessage("Users's IP is in the deny list.");
        } else {
            loginCtx.setAuthenticationOK(true);
        }
    }
    
    /**
     * Search the list of InetAddresses for the client's address.
     *
     * @param request
     *            The ServletReqeust
     *
     * @return <code>true</code> if the client's address is in
     *         <code>ipList</code>
     */
    private boolean searchIpList(final ServletRequest request) {
        
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
            log.error("Error resolving hostname: ", ex);
            return false;
        }
        
        return found;
    }
    
    /**
     * Converts a byte array to a BitSet.
     *
     * The supplied byte array is assumed to have the most signifigant bit in
     * element 0.
     *
     * @param bytes
     *            the byte array with most signifigant bit in element 0.
     *
     * @return the BitSet
     */
    protected static BitSet byteArrayToBitSet(final byte[] bytes) {
        
        BitSet bits = new BitSet();
        
        for (int i = 0; i < bytes.length * 8; i++) {
            if ((bytes[bytes.length - i / 8 - 1] & (1 << (i % 8))) > 0) {
                bits.set(i);
            }
        }
        
        return bits;
    }
}
