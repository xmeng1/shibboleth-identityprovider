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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.util.URLBuilder;

/**
 * Authentication Handler that redirects to servlet protected by a Web Single-Sign-On system.
 */
public class RemoteUserAuthenticationHandler extends AbstractAuthenticationHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(RemoteUserAuthenticationHandler.class);

    /** The URL of the SSO-protected servlet. */
    private String servletURL;

    /**
     * Set the SSO-protected servlet's URL.
     * 
     * @param url The URL of the SSO-protected servlet.
     */
    public void setServletURL(String url) {
        servletURL = url;
    }

    /**
     * Get the URL of the SSO-protected servlet.
     * 
     * @return The URL of the SSO-protected servlet.
     */
    public String getServletURL() {
        return servletURL;
    }

    /** {@inheritDoc} */
    public void login(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {

        // forward control to the servlet.
        try {
            StringBuilder pathBuilder = new StringBuilder();
            pathBuilder.append(httpRequest.getContextPath());
            if (!servletURL.startsWith("/")) {
                pathBuilder.append("/");
            }
            pathBuilder.append(servletURL);

            URLBuilder urlBuilder = new URLBuilder();
            urlBuilder.setScheme(httpRequest.getScheme());
            urlBuilder.setHost(httpRequest.getLocalName());
            urlBuilder.setPort(httpRequest.getLocalPort());
            urlBuilder.setPath(pathBuilder.toString());

            if (log.isDebugEnabled()) {
                log.debug("Redirecting to " + urlBuilder.buildURL());
            }

            httpResponse.sendRedirect(urlBuilder.buildURL());
            return;
        } catch (IOException ex) {
            log.error("RemoteUserAuthenticationHandler: Unable to redirect to remote user authentication servlet.", ex);
        }
    }
}