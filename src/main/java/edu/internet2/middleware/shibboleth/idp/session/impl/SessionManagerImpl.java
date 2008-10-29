/*
 * Copyright 2007 University Corporation for Advanced Internet Development, Inc.
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

import java.security.SecureRandom;

import org.apache.commons.ssl.util.Hex;
import org.opensaml.util.storage.StorageService;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

import edu.internet2.middleware.shibboleth.common.session.LoginEvent;
import edu.internet2.middleware.shibboleth.common.session.LogoutEvent;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.common.util.EventingMapBasedStorageService.AddEntryEvent;
import edu.internet2.middleware.shibboleth.common.util.EventingMapBasedStorageService.RemoveEntryEvent;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/** Manager of IdP sessions. */
public class SessionManagerImpl implements SessionManager<Session>, ApplicationContextAware, ApplicationListener {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SessionManagerImpl.class);

    /** Spring context used to publish login and logout events. */
    private ApplicationContext appCtx;

    /** Number of random bits within a session ID. */
    private final int sessionIDSize = 32;

    /** A {@link SecureRandom} PRNG to generate session IDs. */
    private final SecureRandom prng = new SecureRandom();

    /** Backing service used to store sessions. */
    private StorageService<String, SessionManagerEntry> sessionStore;

    /** Partition in which entries are stored. */
    private String partition;

    /** Lifetime, in milliseconds, of session. */
    private long sessionLifetime;

    /**
     * Constructor.
     * 
     * @param storageService service used to store sessions
     * @param lifetime lifetime, in milliseconds, of sessions
     */
    public SessionManagerImpl(StorageService<String, SessionManagerEntry> storageService, long lifetime) {
        sessionStore = storageService;
        partition = "session";
        sessionLifetime = lifetime;
    }

    /**
     * Constructor.
     * 
     * @param storageService service used to store session
     * @param storageParition partition in which sessions are stored
     * @param lifetime lifetime, in milliseconds, of sessions
     */
    public SessionManagerImpl(StorageService<String, SessionManagerEntry> storageService, String storageParition,
            long lifetime) {
        sessionStore = storageService;
        if (!DatatypeHelper.isEmpty(storageParition)) {
            partition = DatatypeHelper.safeTrim(storageParition);
        } else {
            partition = "session";
        }
        sessionLifetime = lifetime;
    }

    /** {@inheritDoc} */
    public Session createSession() {
        // generate a random session ID
        byte[] sid = new byte[sessionIDSize];
        prng.nextBytes(sid);
        String sessionID = Hex.encode(sid);
        
        byte[] sessionSecret = new byte[16];
        prng.nextBytes(sessionSecret);

        Session session = new SessionImpl(sessionID, sessionSecret, sessionLifetime);
        SessionManagerEntry sessionEntry = new SessionManagerEntry(session, sessionLifetime);
        sessionStore.put(partition, sessionID, sessionEntry);

        MDC.put("idpSessionId", sessionID);
        log.trace("Created session {}", sessionID);
        appCtx.publishEvent(new LoginEvent(session));
        return session;
    }

    /** {@inheritDoc} */
    public Session createSession(String principal) {
        // generate a random session ID
        byte[] sid = new byte[sessionIDSize];
        prng.nextBytes(sid);
        String sessionID = Hex.encode(sid);
        
        byte[] sessionSecret = new byte[16];
        prng.nextBytes(sessionSecret);

        Session session = new SessionImpl(sessionID, sessionSecret, sessionLifetime);
        SessionManagerEntry sessionEntry = new SessionManagerEntry(session, sessionLifetime);
        sessionStore.put(partition, sessionID, sessionEntry);
        
        MDC.put("idpSessionId", sessionID);
        log.trace("Created session {}", sessionID);
        return session;
    }

    /** {@inheritDoc} */
    public void destroySession(String sessionID) {
        if (sessionID == null) {
            return;
        }

        sessionStore.remove(partition, sessionID);
    }

    /** {@inheritDoc} */
    public Session getSession(String sessionID) {
        if (sessionID == null) {
            return null;
        }

        SessionManagerEntry sessionEntry = sessionStore.get(partition, sessionID);
        if (sessionEntry == null) {
            return null;
        }

        if (sessionEntry.isExpired()) {
            destroySession(sessionEntry.getSessionId());
            return null;
        } else {
            return sessionEntry.getSession();
        }
    }

    /** {@inheritDoc} */
    public boolean indexSession(Session session, String index) {
        if (sessionStore.contains(partition, index)) {
            return false;
        }

        SessionManagerEntry sessionEntry = sessionStore.get(partition, session.getSessionID());
        if (sessionEntry == null) {
            return false;
        }

        if (sessionEntry.getSessionIndexes().contains(index)) {
            return true;
        }

        sessionEntry.getSessionIndexes().add(index);
        sessionStore.put(partition, index, sessionEntry);
        log.trace("Added index {} to session {}", index, session.getSessionID());
        return true;
    }

    /** {@inheritDoc} */
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof AddEntryEvent) {
            AddEntryEvent addEvent = (AddEntryEvent) event;
            if (addEvent.getValue() instanceof SessionManagerEntry) {
                SessionManagerEntry sessionEntry = (SessionManagerEntry) addEvent.getValue();
                appCtx.publishEvent(new LoginEvent(sessionEntry.getSession()));
            }
        }

        if (event instanceof RemoveEntryEvent) {
            RemoveEntryEvent removeEvent = (RemoveEntryEvent) event;
            if (removeEvent.getValue() instanceof SessionManagerEntry) {
                SessionManagerEntry sessionEntry = (SessionManagerEntry) removeEvent.getValue();
                appCtx.publishEvent(new LogoutEvent(sessionEntry.getSession()));
            }
        }
    }

    /** {@inheritDoc} */
    public void removeSessionIndex(String index) {
        SessionManagerEntry sessionEntry = sessionStore.remove(partition, index);
        if (sessionEntry != null) {
            log.trace("Removing index {} for session {}", index, sessionEntry.getSessionId());
            sessionEntry.getSessionIndexes().remove(index);
        }
    }

    /** {@inheritDoc} */
    public void setApplicationContext(ApplicationContext applicationContext) {
        ApplicationContext rootContext = applicationContext;
        while (rootContext.getParent() != null) {
            rootContext = rootContext.getParent();
        }
        appCtx = rootContext;
    }
}