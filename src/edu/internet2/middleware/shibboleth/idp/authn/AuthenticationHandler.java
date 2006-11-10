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

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnRequest;

/**
 * Authentication handlers are responsible for authenticating a user using a particular authentication context class.
 * 
 * The request incoming to the authentication handler will contain a {@link AuthnRequest} attribute registered under the
 * name <strong>AuthnRequest</strong>. If the authentication request coming into the IdP is not a SAML 2 request the
 * receiving profile handler will translate the incoming details into a {@link AuthnRequest}.
 * 
 * Upon successfull authentication the handler <strong>must</strong> set a request attribute called <strong>principal</strong>
 * with the principal name of the authenticated user. It must then forward the request/response to the provided return
 * location by means of the
 * {@link RequestDispatcher#forward(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method.
 * 
 * AuthentcationHandlers <strong>MUST NOT</strong> change or add any data to the user's {@link HttpSession} that
 * persists past the process of authenticating the user, that is no additional session data may be added and no existing
 * session data may be changed when the handler redirects back to the return location.
 */
public interface AuthenticationHandler {

    /**
     * Authenticates the user making the request.
     * 
     * @param request user request
     * @param response response to use
     * @param passive whether the authentication must be passive
     * @param force whether the handler must force an authentication
     */
    public void authenticate(HttpServletRequest request, HttpServletResponse response, boolean passive, boolean force);

    /**
     * Gets whether this handler supports passive authentication.
     * 
     * @return whether this handler supports passive authentication
     */
    public boolean supportsPassive();

    /**
     * Gets whether this handler supports the ability to force a user's to authenticate.
     * 
     * @return whether this handler supports the ability to force a user's to authenticate
     */
    public boolean supportsForceAuthentication();

    /**
     * Sets the location to return the user to once authenticated.
     * 
     * @param location location to return the user to once authenticated
     */
    public void setReturnLocation(String location);
}