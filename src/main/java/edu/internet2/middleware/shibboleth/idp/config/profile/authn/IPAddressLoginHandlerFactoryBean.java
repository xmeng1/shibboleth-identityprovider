/*
 * Copyright 2008 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.config.profile.authn;

import java.util.List;

import edu.internet2.middleware.shibboleth.idp.authn.provider.IPAddressLoginHandler;

/**
 * Spring factory for {@link IPAddressLoginHandler}.
 */
public class IPAddressLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    /** The list of denied or permitted IPs. */
    private List<String> addresses;

    /** The username to use for IP-address "authenticated" users. */
    private String username;

    /** Are the IPs in ipList a permitted list or a deny list. */
    private boolean defaultDeny;

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        IPAddressLoginHandler handler = new IPAddressLoginHandler();
        handler.setUsername(getUsername());
        handler.setEntries(getAddresses(), isDefaultDeny());
        populateHandler(handler);
        return handler;
    }

    /** {@inheritDoc} */
    public Class getObjectType() {
        return IPAddressLoginHandler.class;
    }

    /**
     * Get the list of denied or permitted IPs.
     * 
     * @return list of denied or permitted IPs
     */
    public List<String> getAddresses() {
        return addresses;
    }

    /**
     * Set the list of denied or permitted IPs.
     * 
     * @param newAddresses list of denied or permitted IPs
     */
    public void setAddresses(List<String> newAddresses) {
        addresses = newAddresses;
    }

    /**
     * Get the username to use for IP-address "authenticated" users.
     * 
     * @return username to use for IP-address "authenticated" users
     */
    public String getUsername() {
        return username;
    }

    /**
     * Set the username to use for IP-address "authenticated" users.
     * 
     * @param newUsername username to use for IP-address "authenticated" users
     */
    public void setUsername(String newUsername) {
        username = newUsername;
    }

    /**
     * Get whether the IPs in ipList a permitted list or a deny list.
     * 
     * @return whether the IPs in ipList a permitted list or a deny list
     */
    public boolean isDefaultDeny() {
        return defaultDeny;
    }

    /**
     * Set whether the IPs in ipList a permitted list or a deny list.
     * 
     * @param newDefaultDeny whether the IPs in ipList a permitted list or a deny list.
     */
    public void setDefaultDeny(boolean newDefaultDeny) {
        defaultDeny = newDefaultDeny;
    }

}
