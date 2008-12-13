/*
 * Copyright 2006 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.session.impl;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import edu.internet2.middleware.shibboleth.common.session.impl.AbstractSession;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/** Session information for user logged into the IdP. */
public class SessionImpl extends AbstractSession implements Session {

    /** Serial version UID. */
    private static final long serialVersionUID = 2927868242208211623L;

    /** Secret key associated with the session. */
    private byte[] sessionSecret;

    /** The list of methods used to authenticate the user. */
    private Map<String, AuthenticationMethodInformation> authnMethods;

    /** The list of services to which the user has logged in. */
    private Map<String, ServiceInformation> servicesInformation;

    /**
     * Constructor.
     * 
     * @param sessionId ID of the session
     * @param secret a secret to associate with the session
     * @param timeout inactivity timeout for the session in milliseconds
     */
    public SessionImpl(String sessionId, byte[] secret, long timeout) {
        super(sessionId, timeout);

        sessionSecret = secret;
        authnMethods = new ConcurrentHashMap<String, AuthenticationMethodInformation>(2);
        servicesInformation = new ConcurrentHashMap<String, ServiceInformation>(2);
    }

    /** {@inheritDoc} */
    public synchronized byte[] getSessionSecret() {
        return sessionSecret;
    }

    /** {@inheritDoc} */
    public synchronized Map<String, AuthenticationMethodInformation> getAuthenticationMethods() {
        return authnMethods;
    }

    /** {@inheritDoc} */
    public synchronized Map<String, ServiceInformation> getServicesInformation() {
        return servicesInformation;
    }

    /**
     * Gets the service information for the given entity ID.
     * 
     * @param entityId entity ID to retrieve the service information for
     * 
     * @return the service information or null
     */
    public synchronized ServiceInformation getServiceInformation(String entityId) {
        return servicesInformation.get(entityId);
    }
}