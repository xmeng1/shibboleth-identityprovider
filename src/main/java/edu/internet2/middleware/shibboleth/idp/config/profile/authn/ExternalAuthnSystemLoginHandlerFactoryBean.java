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

package edu.internet2.middleware.shibboleth.idp.config.profile.authn;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;

/**
 * Spring factory for {@link ExternalAuthnSystemLoginHandler}.
 */
public class ExternalAuthnSystemLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    /** The context-relative path to the Filter, Servlet, or JSP that triggers the external authentication system. */
    private String externalAuthnPath;

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

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        ExternalAuthnSystemLoginHandler handler = new ExternalAuthnSystemLoginHandler();
        handler.setExternalAuthnPath(getExternalAuthnPath());
        populateHandler(handler);
        return handler;
    }
}