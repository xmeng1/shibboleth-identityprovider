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

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;

/**
 * Spring factory for {@link ExternalAuthnSystemLoginHandler}.
 */
public class ExternalAuthnSystemLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    /** The context-relative path to the Filter, Servlet, or JSP that triggers the external authentication system. */
    private String externalAuthnPath;
    
    /** Whether this handler supports forced re-authentication. */
    private boolean supportsForcedAuthentication;

    /** Whether this handler supports passive authentication. */
    private boolean supportsPassive;

    /** {@inheritDoc} */
    public Class getObjectType() {
        return ExternalAuthnSystemLoginHandler.class;
    }

    /**
     * Get context-relative path to the Filter, Servlet, or JSP that triggers the external authentication system.
     * 
     * @return context-relative path to the Filter, Servlet, or JSP that triggers the external authentication system
     */
    public String getExternalAuthnPath() {
        return externalAuthnPath;
    }

    /**
     * Set context-relative path to the Filter, Servlet, or JSP that triggers the external authentication system.
     * 
     * @param path context-relative path to the Filter, Servlet, or JSP that triggers the external authentication
     *            system, may not be null or empty
     */
    public void setExternalAuthnPath(String path) {
        externalAuthnPath = path;
    }
    
    /**
     * Gets whether this handler supposed forced re-authentication.
     * 
     * @return whether this handler supposed forced re-authentication
     */
    public boolean supportsForcedAuthentication() {
        return supportsForcedAuthentication;
    }

    /**
     * Sets whether this handler supports forced re-authentication.
     * 
     * @param supported whether this handler supports forced re-authentication
     */
    public void setSupportsForcedAuthentication(boolean supported) {
        supportsForcedAuthentication = supported;
    }

    /**
     * Gets whether this handler supports passive authentication.
     * 
     * @return whether this handler supports passive authentication
     */
    public boolean supportsPassiveAuthentication() {
        return supportsPassive;
    }

    /**
     * Sets whether this handler supports passive authentication.
     * 
     * @param supported whether this handler supports passive authentication.
     */
    public void setSupportsPassiveAuthentication(boolean supported) {
        supportsPassive = supported;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        ExternalAuthnSystemLoginHandler handler = new ExternalAuthnSystemLoginHandler();
        handler.setExternalAuthnPath(getExternalAuthnPath());
        handler.setSupportsForceAuthentication(supportsForcedAuthentication);
        handler.setSupportsPassive(supportsPassive);
        populateHandler(handler);
        return handler;
    }
}