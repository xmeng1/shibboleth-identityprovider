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

import java.util.List;

import org.springframework.beans.factory.config.AbstractFactoryBean;

import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;

/**
 * Base class for authentication handler factory beans.
 */
public abstract class AbstractLoginHandlerFactoryBean extends AbstractFactoryBean {

    /** Authentication methods supported by the handler. */
    private List<String> authenticationMethods;

    /** Duration of the authentication, in minutes. */
    private int authenticationDuration;

    /**
     * Gets the duration of the authentication, in minutes.
     * 
     * @return duration of the authentication, in minutes
     */
    public int getAuthenticationDuration() {
        return authenticationDuration;
    }

    /**
     * Sets the duration of the authentication, in minutes.
     * 
     * @param duration duration of the authentication, in minutes
     */
    public void setAuthenticationDuration(int duration) {
        this.authenticationDuration = duration;
    }

    /**
     * Gets the authentication methods supported by the handler.
     * 
     * @return authentication methods supported by the handler
     */
    public List<String> getAuthenticationMethods() {
        return authenticationMethods;
    }

    /**
     * Sets the authentication methods supported by the handler.
     * 
     * @param methods authentication methods supported by the handler
     */
    public void setAuthenticationMethods(List<String> methods) {
        this.authenticationMethods = methods;
    }

    /**
     * Populates the authentication duration and methods of the handler.
     * 
     * @param handler the authentication handler to populate
     */
    protected void populateHandler(AbstractLoginHandler handler) {
        if (authenticationMethods != null) {
            handler.getSupportedAuthenticationMethods().addAll(authenticationMethods);
        }
        handler.setAuthenticationDurection(authenticationDuration * 60 * 1000);
    }
}
