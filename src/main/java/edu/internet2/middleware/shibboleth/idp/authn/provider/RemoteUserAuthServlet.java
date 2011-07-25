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

/** Extracts the REMOTE_USER and places it in a request attribute to be used by the authentication engine. */
public class RemoteUserAuthServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -6153665874235557534L;    

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(RemoteUserAuthServlet.class);

    /** {@inheritDoc} */
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        String principalName = DatatypeHelper.safeTrimOrNullString(httpRequest.getRemoteUser());
        if(principalName != null){
            log.debug("Remote user identified as {} returning control back to authentication engine", principalName);
            httpRequest.setAttribute(LoginHandler.PRINCIPAL_KEY, new UsernamePrincipal(principalName));
        }else{
            log.debug("No remote user information was present in the request");
        }

        AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
    }
}