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

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import edu.internet2.middleware.shibboleth.common.session.SessionManager;

/**
 * A listener that listens for the destruction of {@link HttpSession}s. This allows the {@link SessionManager} to
 * appropriately destroy a Shibboleth session whether the HTTP session is destroyed explicitly or through inactivity.
 */
public class ContainerSessionListener implements HttpSessionListener {

    /** {@inheritDoc} */
    public void sessionCreated(HttpSessionEvent httpSessionEvent) {
        // we don't care about session creations
    }

    /** {@inheritDoc} */
    public void sessionDestroyed(HttpSessionEvent httpSessionEvent) {
        HttpSession httpSession = httpSessionEvent.getSession();
        SessionManager<Session> sessionManager = (SessionManager<Session>) httpSession.getServletContext()
                .getAttribute("sessionManager");

        sessionManager.destroySession((String) httpSession.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE));
    }
}