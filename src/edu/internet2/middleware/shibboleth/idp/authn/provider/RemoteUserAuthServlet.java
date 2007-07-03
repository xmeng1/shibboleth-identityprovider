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

package edu.internet2.middleware.shibboleth.idp.authn.provider;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;

/**
 * Extracts the REMOTE_USER and places it in a request attribute to be used by the authentication engine.
 */
public class RemoteUserAuthServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = 1745454095756633626L;

    /** Class logger. */
    private final Logger log = Logger.getLogger(RemoteUserAuthServlet.class);

    /** {@inheritDoc} */
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        String principalName = httpRequest.getRemoteUser();

        if (log.isDebugEnabled()) {
            log.debug("Remote user identified as " + principalName
                            + " returning control back to authentication engine");
        }
        httpRequest.setAttribute(AuthenticationHandler.PRINCIPAL_NAME_KEY, httpRequest.getRemoteUser());
        AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
    }
}