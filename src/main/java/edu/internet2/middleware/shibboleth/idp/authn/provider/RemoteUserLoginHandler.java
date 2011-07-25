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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * Authentication Handler that redirects to servlet protected by a Web Single-Sign-On system.
 */
public class RemoteUserLoginHandler extends AbstractLoginHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(RemoteUserLoginHandler.class);

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
            String profileUrl = HttpServletHelper.getContextRelativeUrl(httpRequest, servletURL).buildURL();

            log.debug("Redirecting to {}", profileUrl);
            httpResponse.sendRedirect(profileUrl);
            return;
        } catch (IOException ex) {
            log.error("Unable to redirect to remote user authentication servlet.", ex);
        }
    }
}