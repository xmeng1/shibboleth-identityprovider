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

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

/**
 * This servlet should be protected by a filter which populates REMOTE_USER.
 * The serlvet will then set the remote user field in a LoginContext.
 */
public class RemoteUserAuthServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(RemoteUserAuthServlet.class);
    
    public RemoteUserAuthServlet() {
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        
        HttpSession httpSession = request.getSession();
        
        Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (!(o instanceof LoginContext)) {
            log.error("RemoteUSerAuthServlet - Invalid login context object -- object is not an instance of LoginContext");
            return; // where this will return to, I don't know.
        }
        
        LoginContext loginContext = (LoginContext)o;

        loginContext.setAuthenticationInstant(new DateTime());
        
        String remoteUser = request.getRemoteUser();
        if (remoteUser == null || remoteUser.length() == 0) {
            loginContext.setAuthenticationOK(false);;
        } else {
            loginContext.setAuthenticationOK(true);
            loginContext.setUserID(remoteUser);
        }
        
        // redirect the user back to the AuthenticationManager
        try {
            RequestDispatcher dispatcher =
                    request.getRequestDispatcher(loginContext.getAuthenticationManagerURL());
            dispatcher.forward(request, response);
        } catch (ServletException ex) {
            log.error("RemoteUserAuthServlet: Error redirecting back to AuthenticationManager", ex);
        }
    }
        
    
}
