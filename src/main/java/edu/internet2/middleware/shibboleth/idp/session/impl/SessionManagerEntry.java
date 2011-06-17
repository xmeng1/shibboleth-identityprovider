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

package edu.internet2.middleware.shibboleth.idp.session.impl;

import java.util.List;
import java.util.Vector;

import org.joda.time.DateTime;
import org.opensaml.util.storage.AbstractExpiringObject;

import edu.internet2.middleware.shibboleth.idp.session.Session;

/** Session store entry. */
public class SessionManagerEntry extends AbstractExpiringObject {

    /** Serial version UID. */
    private static final long serialVersionUID = -9160494097986587739L;

    /** User's session. */
    private Session userSession;

    /** Indexes for this session. */
    private List<String> indexes;

    /**
     * Constructor.
     * 
     * @param session user session
     * @param lifetime lifetime of session
     */
    public SessionManagerEntry(Session session, long lifetime) {
        super(new DateTime().plus(lifetime));
        userSession = session;
        indexes = new Vector<String>();
        indexes.add(userSession.getSessionID());
    }

    /**
     * Gets the user session.
     * 
     * @return user session
     */
    public Session getSession() {
        return userSession;
    }

    /**
     * Gets the ID of the user session.
     * 
     * @return ID of the user session
     */
    public String getSessionId() {
        return userSession.getSessionID();
    }

    /**
     * Gets the list of indexes for this session.
     * 
     * @return list of indexes for this session
     */
    public List<String> getSessionIndexes() {
        return indexes;
    }

    /** {@inheritDoc} */
    public DateTime getExpirationTime() {
        return userSession.getLastActivityInstant().plus(userSession.getInactivityTimeout());
    }
}