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
import javax.servlet.http.HttpSession;

/**
 * Authentication handlers are responsible for authenticating a user using a particular authentication context class.
 */
public interface AuthenticationHandler {

    /**
     * Authenticates the user making the request.  Upon successfull authentication the handler <strong>must</strong>
     * set an {@link HttpSession} attribute called "principal" with the principal name of the authenticated user.
     * 
     * @param request user request
     * @param response response to use
     * @param passive whether the authentication must be passive
     */
	public void authenticate(HttpServletRequest request, HttpServletResponse response, boolean passive);
	
    /**
     * Gets whether this handler supports passive authentication.
     * 
     * @return whether this handler supports passive authentication
     */
	public boolean supportsPassive();
	
    /**
     * Gets the authentication context class supported by this handler.
     * 
     * @return authentication context class supported by this handler
     */
	public String supportedAuthenticationContextClass();
    
    
    public void setReturnPath(String path);
}