/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

import java.util.Map;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;

/**
 * Spring factory for {@link ExternalAuthnSystemLoginHandler}.
 */
public class ExternalAuthnSystemLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    /** Path to protected servlet. */
    private String protectedServletPath;

    /** Static query parameters added to the request to the external authentication system invocation. */
    private Map<String, String> queryParams;

    /** {@inheritDoc} */
    public Class getObjectType() {
        return ExternalAuthnSystemLoginHandler.class;
    }

    /**
     * Gets the path to protected Servlet.
     * 
     * @return path to protected servlet
     */
    public String getProtectedServletPath() {
        return protectedServletPath;
    }

    /**
     * Sets the path to protected servlet.
     * 
     * @param path path to protected servlet
     */
    public void setProtectedServletPath(String path) {
        protectedServletPath = path;
    }

    /**
     * Gets the static query parameters added to the request to the external authentication system invocation.
     * 
     * @return static query parameters added to the request to the external authentication system invocation
     */
    public Map<String, String> getQueryParams() {
        return queryParams;
    }

    /**
     * Sets the static query parameters added to the request to the external authentication system invocation.
     * 
     * @param params static query parameters added to the request to the external authentication system invocation
     */
    public void setQueryParams(Map<String, String> params) {
        queryParams = params;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        ExternalAuthnSystemLoginHandler handler = new ExternalAuthnSystemLoginHandler();
        handler.setProtectedPath(getProtectedServletPath());
        handler.setQueryParameters(queryParams);
        populateHandler(handler);
        return handler;
    }
}