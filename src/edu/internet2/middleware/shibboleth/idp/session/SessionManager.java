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

package edu.internet2.middleware.shibboleth.idp.session;

/**
 * Session managers are responsible for creating, managing, and destroying Shibboleth IdP sessions.
 */
public interface SessionManager {

    /**
     * Creates a Shibboleth session.
     * 
     * @return a Shibboleth session
     */
    public Session createSession();
    
    /**
     * Gets the user's session based on session's ID.
     * 
     * @param sessionID the ID of the session
     * 
     * @return the session
     */
    public Session getSession(String sessionID);
    
    /**
     * Destroys the session.
     * 
     * @param sessionID the ID of the session.
     */
    public void destroySession(String sessionID);
}