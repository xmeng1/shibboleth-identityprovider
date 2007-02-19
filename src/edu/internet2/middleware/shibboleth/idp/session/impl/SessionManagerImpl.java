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

package edu.internet2.middleware.shibboleth.idp.session.impl;

import java.net.InetAddress;
import java.util.HashMap;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import edu.internet2.middleware.shibboleth.common.session.LoginEvent;
import edu.internet2.middleware.shibboleth.common.session.LogoutEvent;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * Manager of IdP sessions.
 */
public class SessionManagerImpl implements SessionManager<Session>, ApplicationContextAware {

    /** Spring context used to publish login and logout events. */
    private ApplicationContext appCtx;
    
    /** Currently active sessions. */
    private HashMap<String, Session> activeSessions;
    
    /** Constructor. */
    public SessionManagerImpl(){
        activeSessions = new  HashMap<String, Session>();
    }
    
    /** {@inheritDoc} */
    public void setApplicationContext(ApplicationContext applicationContext) {
        appCtx = applicationContext;
    }
    
    /** {@inheritDoc} */
    public Session createSession(InetAddress presenter, String principal) {
        SessionImpl session = new SessionImpl(presenter, principal);
        activeSessions.put(session.getSessionID(), session);
        appCtx.publishEvent(new LoginEvent(session));
        return session;
    }

    /** {@inheritDoc} */
    public void destroySession(String sessionID) {
        Session session = activeSessions.remove(sessionID);
        if(session != null){
            appCtx.publishEvent(new LogoutEvent(session));
        }
    }

    /** {@inheritDoc} */
    public Session getSession(String sessionID) {
        return activeSessions.get(sessionID);
    }
}