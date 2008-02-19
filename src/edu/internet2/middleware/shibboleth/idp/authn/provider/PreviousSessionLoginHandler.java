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

package edu.internet2.middleware.shibboleth.idp.authn.provider;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.util.URLBuilder;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;

/**
 * Login handler that is called when user is logged in under a previously existing session.
 * 
 * This login handler can optionally redirect the browser to a given URL. This provides a mechanism for extensions to
 * hook into the authentication process on every request. If this option is used and the servlet to which the browser is
 * redirected does not take visible control of the request be sure to indicate passive authentication support by means
 * of {@link PreviousSessionLoginHandler#setSupportsPassive(boolean)}.
 * 
 * When the servlet has completed it's work it <strong>MUST</strong> call
 * {@link AuthenticationEngine#returnToAuthenticationEngine(HttpServletRequest, HttpServletResponse)} in order to
 * transfer control back to the authentication engine.
 */
public class PreviousSessionLoginHandler extends AbstractLoginHandler {

    /** PreviousSession authentication method URI. */
    public static final String PREVIOUS_SESSION_AUTHN_METHOD = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession";

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
    }

    /**
     * Get the path of the servlet to which the user agent may be redirected.
     * 
     * @return path of the servlet to which the user agent may be redirected
     */
    public String getServletPath() {
        return servletPath;
    }

    /**
     * Set the path of the servlet to which the user agent may be redirected.
     * 
     * @param path path of the servlet to which the user agent may be redirected
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
        if (servletPath == null) {
            AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
        } else {
            try {
                StringBuilder pathBuilder = new StringBuilder();
                pathBuilder.append(httpRequest.getContextPath());
                if (!servletPath.startsWith("/")) {
                    pathBuilder.append("/");
                }
                pathBuilder.append(servletPath);

                URLBuilder urlBuilder = new URLBuilder();
                urlBuilder.setScheme(httpRequest.getScheme());
                urlBuilder.setHost(httpRequest.getLocalName());
                urlBuilder.setPort(httpRequest.getLocalPort());
                urlBuilder.setPath(pathBuilder.toString());

                log.debug("Redirecting to {}", urlBuilder.buildURL());
                httpResponse.sendRedirect(urlBuilder.buildURL());
                return;
            } catch (IOException ex) {
                log.error("Unable to redirect to previous session authentication servlet.", ex);
            }
        }
    }
}