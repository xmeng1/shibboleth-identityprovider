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

package edu.internet2.middleware.shibboleth.idp.authn;

import java.util.Map;

import org.opensaml.xml.util.Pair;

/**
 * Manager for registering and retrieving authentication handlers.
 */
public interface AuthenticationHandlerManager {

    /**
     * Gets the registered authentication handlers.
     * 
     * @return registered authentication handlers
     */
    public Map<String, AuthenticationHandler> getAuthenticationHandlers();

    /**
     * Gets the authentication handler appropriate for the given loging context. The mechanism used to determine the
     * "appropriate" handler is implementation specific.
     * 
     * @param loginContext current login context
     * 
     * @return authentication method URI and handler appropriate for given login context
     */
    public Pair<String, AuthenticationHandler> getAuthenticationHandler(LoginContext loginContext);
}