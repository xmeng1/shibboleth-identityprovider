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

package edu.internet2.middleware.shibboleth.idp.authn.impl;


import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;


/**
 * Wrapper class around {@link AuthenticationHandler} metadata.
 *
 * This class wraps three pieces of metadata:
 * <code>supportsPassive</code>, a boolean indicating if the handler supports passive authN
 * <code>supportsForce</code>, a boolean indicating if the handler supports forced authN
 * <code>handler</code>, a reference to an {@link AuthenticationHandler} servlet
 */
public class AuthenticationHandlerInfo {
    
    /** does the handler support passive authN */
    private boolean supportsPassive;
    
    /** does the handler support forced authN */
    private boolean supportsForce;
    
    /** the {@link AuthenticationHandler itself */
    private AuthenticationHandler handler;
    
    
    /**
     * constructor.
     *
     * @param handler The {@link AuthenticationHandler} reference.
     * @param supportsPassive does the handler supports passive authN
     * @param supportsForce does the handler supports forced authN
     *
     * @throws IllegalArgumentException if handler is <code>null</code>
     */
    public AuthenticationHandlerInfo(AuthenticationHandler handler,
            boolean supportsPassive, boolean supportsForce) throws IllegalArgumentException {
        
        if (handler == null) {
            throw new IllegalArgumentException("handler is null");
        }
        
        
        this.supportsPassive = supportsPassive;
        this.supportsForce = supportsForce;
    }
    
    
    /**
     * Getter for the {@link AuthenticationHandler} itself.
     *
     * @return the AuthenticationHandler reference.
     */
    public AuthenticationHandler getHandler() {
        return this.handler;
    }
    
    
    /**
     * Getter for supportsPassive.
     *
     * @return if the handler supports passive authN.
     */
    public boolean supportsPassive() {
        return this.supportsPassive;
    }
    
    
    /**
     * Getter for supportsForce
     *
     * @return if the handler supports forced authN.
     */
    public boolean supportsForce() {
        return this.supportsForce;
    }
}