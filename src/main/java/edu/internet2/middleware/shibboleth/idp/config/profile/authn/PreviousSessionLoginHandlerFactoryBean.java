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

package edu.internet2.middleware.shibboleth.idp.config.profile.authn;

import edu.internet2.middleware.shibboleth.idp.authn.provider.PreviousSessionLoginHandler;

/**
 * Spring factory for {@link PreviousSessionLoginHandler}.
 */
public class PreviousSessionLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    /** Path to protected servlet. */
    private String servletPath;

    /** Whether the login handler supports passive authentication. */
    private boolean supportPassiveAuth;

    /** Whether the login handler will report its authentication method as PreviousSession. */
    private boolean reportPreviousSessionAuthnMethod;

    /** {@inheritDoc} */
    public Class getObjectType() {
        return PreviousSessionLoginHandler.class;
    }

    /**
     * Gets the path of the servlet to which the user agent may be redirected.
     * 
     * @return path of the servlet to which the user agent may be redirected
     */
    public String getServletPath() {
        return servletPath;
    }

    /**
     * Sets the path of the servlet to which the user agent may be redirected.
     * 
     * @param path path of the servlet to which the user agent may be redirected
     */
    public void setServletPath(String path) {
        servletPath = path;
    }

    /**
     * Gets whether the login handler supports passive authentication.
     * 
     * @return whether the login handler supports passive authentication
     */
    public boolean supportsPassiveAuth() {
        return supportPassiveAuth;
    }

    /**
     * Sets whether the login handler supports passive authentication.
     * 
     * @param supported whether the login handler supports passive authentication
     */
    public void setSupportsPassiveAuth(boolean supported) {
        supportPassiveAuth = supported;
    }

    /**
     * Gets whether the login handler will report its authentication method as PreviousSession.
     * 
     * @return whether the login handler will report its authentication method as PreviousSession
     */
    public boolean reportPreviousSessionAuthnMethod() {
        return reportPreviousSessionAuthnMethod;
    }

    /**
     * Sets whether the login handler will report its authentication method as PreviousSession.
     * 
     * @param report whether the login handler will report its authentication method as PreviousSession
     */
    public void setReportPreviousSessionAuthnMethod(boolean report) {
        reportPreviousSessionAuthnMethod = report;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        PreviousSessionLoginHandler handler = new PreviousSessionLoginHandler();
        handler.setServletPath(getServletPath());
        handler.setSupportsPassive(supportsPassiveAuth());
        handler.setReportPreviousSessionAuthnMethod(reportPreviousSessionAuthnMethod());
        populateHandler(handler);
        return handler;
    }
}