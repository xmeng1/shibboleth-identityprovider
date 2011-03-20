/*
 * Copyright 2011 University Corporation for Advanced Internet Development, Inc.
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

import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;

/**
 * Extracts the REMOTE_USER and, optionally, the method used to authentication the user and places the information in
 * request attributes used by the authentication engine.
 */
public class ExternalAuthnSystemServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -6153665874235557534L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ExternalAuthnSystemServlet.class);

    /** {@inheritDoc} */
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        String principalName = httpRequest.getRemoteUser();

        log.debug("User identified as {} returning control back to authentication engine", principalName);
        httpRequest.setAttribute(LoginHandler.PRINCIPAL_KEY, new UsernamePrincipal(principalName));

        String authnMethod = DatatypeHelper.safeTrimOrNullString(httpRequest
                .getHeader(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM));
        if (authnMethod != null) {
            log.debug("User {} authenticated by the method {}", principalName, authnMethod);
            httpRequest.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authnMethod);
        }

        AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
    }
}