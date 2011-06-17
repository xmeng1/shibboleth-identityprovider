/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
import edu.internet2.middleware.shibboleth.idp.util.IPRange;

/**
 * Spring factory for {@link IPAddressLoginHandler}.
 */
public class IPAddressLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    /** The username to use for IP-address "authenticated" users. */
    private String authenticatedUser;

    /** List of configured IP ranged. */
    private List<IPRange> ipRanges;

    /** Whether a user is "authenticated" if their IP address is within a configured IP range. */
    private boolean ipInRangeIsAuthenticated;

    /** {@inheritDoc} */
    public Class getObjectType() {
        return IPAddressLoginHandler.class;
    }
    
    /**
     * @param user The authenticatedUser to set.
     */
    public void setAuthenticatedUser(String user) {
        authenticatedUser = user;
    }

    /**
     * @param ranges The ipRanges to set.
     */
    public void setIpRanges(List<IPRange> ranges) {
        ipRanges = ranges;
    }

    /**
     * @param authenticated The ipInRangeIsAuthenticated to set.
     */
    public void setIpInRangeIsAuthenticated(boolean authenticated) {
        ipInRangeIsAuthenticated = authenticated;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        IPAddressLoginHandler handler = new IPAddressLoginHandler(authenticatedUser, ipRanges, ipInRangeIsAuthenticated);
        populateHandler(handler);
        return handler;
    }
}