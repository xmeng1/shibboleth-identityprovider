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

package edu.internet2.middleware.shibboleth.idp.authn;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Authentication handlers authenticate a user in an implementation specific manner. Some examples of this might be by
 * collecting a user name and password and validating it against an LDAP directory or collecting and validating a client
 * certificate or one-time password.
 * 
 * After the handler has authenticated the user it <strong>MUST</strong> bind the user's principal name to the
 * {@link HttpServletRequest} attribute identified by {@link AuthenticationHandler#PRINCIPAL_NAME_KEY}. The handler may
 * also bind an error message, if an error occurred during authentication to the request attribute identified by
 * {@link AuthenticationHandler#AUTHENTICATION_ERROR_KEY}. Finally, the handler must return control to the
 * authentication engine by invoking
 * {@link AuthenticationEngine#returnToAuthenticationEngine(HttpServletRequest, HttpServletResponse)}. After which the
 * authentication handler must immediately return.
 * 
 * Handlers <strong>MUST NOT</strong> change or add any data to the user's {@link javax.servlet.http.HttpSession} that
 * persists past the process of authenticating the user, that is no additional session data may be added and no existing
 * session data may be changed when the handler returns control to the authentication engine.
 */
public interface AuthenticationHandler {

    /** Request attribute to which user's principal name should be bound. */
    public static final String PRINCIPAL_NAME_KEY = "principal";

    /** Request attribute to which an error message may be bound. */
    public static final String AUTHENTICATION_ERROR_KEY = "authnError";

    /**
     * Gets the length of time, in milliseconds, after which a user authenticated by this handler should be
     * re-authenticated.
     * 
     * @return length of time, in milliseconds, after which a user should be re-authenticated
     */
    public long getAuthenticationDuration();

    /**
     * Gets whether this handler supports passive authentication.
     * 
     * @return whether this handler supports passive authentication
     */
    public boolean supportsPassive();

    /**
     * Returns if this handler supports the ability to force a user to (re-)authenticate.
     * 
     * @return if this handler can force a user to (re-)authenticate.
     */
    public boolean supportsForceAuthentication();

    /**
     * Authenticate the user making the request.
     * 
     * @param httpRequest user request
     * @param httpResponse response to user
     */
    public void login(HttpServletRequest httpRequest, HttpServletResponse httpResponse);

    /**
     * Logs out the given user from the authentication mechanism represented by this handler.
     * 
     * @param request user request
     * @param response response to user
     * @param principal principal named as returned during authentication
     */
    public void logout(HttpServletRequest request, HttpServletResponse response, String principal);
}