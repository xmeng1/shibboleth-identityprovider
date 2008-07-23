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

package edu.internet2.middleware.shibboleth.idp.authn;

/**
 * Exception indicating that passive authentication was requested but could not be performed.
 */
public class PassiveAuthenticationException extends AuthenticationException {

    /** Serial version UID. */
    private static final long serialVersionUID = 8333401210912649476L;

    /** Constructor. */
    public PassiveAuthenticationException() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param message exception message
     */
    public PassiveAuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructor.
     * 
     * @param wrappedException exception to be wrapped by this one
     */
    public PassiveAuthenticationException(Exception wrappedException) {
        super(wrappedException);
    }

    /**
     * Constructor.
     * 
     * @param message exception message
     * @param wrappedException exception to be wrapped by this one
     */
    public PassiveAuthenticationException(String message, Exception wrappedException) {
        super(message, wrappedException);
    }
}