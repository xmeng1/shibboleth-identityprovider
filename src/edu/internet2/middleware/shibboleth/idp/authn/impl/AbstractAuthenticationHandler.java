/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;

/**
 * Base class for authentication handlers.
 */
public abstract class AbstractAuthenticationHandler implements AuthenticationHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(AbstractAuthenticationHandler.class);

    /** Length of time, in milliseconds, after which a user should be re-authenticated. */
    private long authenticationDuration;

    /** Whether this handler supports foreced re-authentication. */
    private boolean supportsForceAuthentication;

    /** Whether this handler supports passive authentication. */
    private boolean supportsPassive;

    /** {@inheritDoc} */
    public long getAuthenticationDuration() {
        return authenticationDuration;
    }

    /**
     * Sets the length of time, in milliseconds, after which a user should be re-authenticated.
     * 
     * @param duration length of time, in milliseconds, after which a user should be re-authenticated
     */
    public void setAuthenticationDurection(long duration) {
        authenticationDuration = duration;
    }

    /** {@inheritDoc} */
    public boolean supportsForceAuthentication() {
        return supportsForceAuthentication;
    }

    /**
     * Sets whether this handler supports foreced re-authentication.
     * 
     * @param supported whether this handler supports foreced re-authentication
     */
    public void setSupportsForceAuthentication(boolean supported) {
        supportsForceAuthentication = supported;
    }

    /** {@inheritDoc} */
    public boolean supportsPassive() {
        return supportsPassive;
    }

    /**
     * Sets whether this handler supports passive authentication.
     * 
     * @param supported whether this handler supports passive authentication.
     */
    public void setSupportsPassive(boolean supported) {
        supportsPassive = supported;
    }

    /** {@inheritDoc} */
    public void logout(HttpServletRequest request, HttpServletResponse response, String principal) {
        // logout not yet supported
    }
}