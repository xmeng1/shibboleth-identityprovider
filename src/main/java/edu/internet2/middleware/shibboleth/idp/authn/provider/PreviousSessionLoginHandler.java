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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/** Login handler that is called when user is logged in under a previously existing session. */
public class PreviousSessionLoginHandler extends AbstractLoginHandler {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PreviousSessionLoginHandler.class);

    /** The path of the servlet to which the user agent may be redirected. */
    private String servletPath;

    /** Whether to report the authentication method as PreviousSession. */
    private boolean reportPreviousSessionAuthnMethod;

    /** Constructor. */
    public PreviousSessionLoginHandler() {
        super();
        servletPath = null;
        setSupportsPassive(true);
        setSupportsForceAuthentication(false);
    }

    /**
     * Get the path of the servlet to which the user agent may be redirected.
     * 
     * @return path of the servlet to which the user agent may be redirected
     * 
     * @deprecated
     */
    public String getServletPath() {
        return servletPath;
    }

    /**
     * Set the path of the servlet to which the user agent may be redirected.
     * 
     * @param path path of the servlet to which the user agent may be redirected
     * 
     * @deprecated
     */
    public void setServletPath(String path) {
        servletPath = DatatypeHelper.safeTrimOrNullString(path);
    }

    /**
     * Gets whether to use PreviousSession as the users authentication method.
     * 
     * @return whether to use PreviousSession as the users authentication method
     */
    public boolean reportPreviousSessionAuthnMethod() {
        return reportPreviousSessionAuthnMethod;
    }

    /**
     * Sets whether to use PreviousSession as the users authentication method.
     * 
     * @param report whether to use PreviousSession as the users authentication method
     */
    public void setReportPreviousSessionAuthnMethod(boolean report) {
        reportPreviousSessionAuthnMethod = report;
    }

    /** {@inheritDoc} */
    public boolean supportsPassive() {
        if (servletPath == null) {
            return true;
        }

        return super.supportsPassive();
    }

    /** {@inheritDoc} */
    public void login(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        if (reportPreviousSessionAuthnMethod) {
            httpRequest.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
        }
        
        Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        if(idpSession == null){
            log.warn("No existing IdP session available.");
            httpRequest.setAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY, "No existing IdP session available");
        }else{
            log.debug("Using existing IdP session for {}", idpSession.getPrincipalName());
            httpRequest.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, idpSession.getPrincipalName());
        }

        AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
    }
}