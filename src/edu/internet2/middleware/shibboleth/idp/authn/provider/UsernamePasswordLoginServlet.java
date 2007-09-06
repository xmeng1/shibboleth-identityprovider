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

package edu.internet2.middleware.shibboleth.idp.authn.provider;

import java.io.IOException;
import java.security.Principal;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.util.URLBuilder;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;

/**
 * This servlet should be protected by a filter which populates REMOTE_USER. The serlvet will then set the remote user
 * field in a LoginContext.
 */
public class UsernamePasswordLoginServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -572799841125956990L;

    /** Class logger. */
    private final Logger log = Logger.getLogger(RemoteUserAuthServlet.class);

    /** Name of JAAS configuration used to authenticate users. */
    private final String jaasConfigName = "ShibUserPassAuth";
    
    /** Login page name. */
    private final String loginPage = "login.jsp";

    /** HTTP request parameter containing the user name. */
    private final String usernameAttribute = "j_username";

    /** HTTP request parameter containing the user's password. */
    private final String passwordAttribute = "j_password";

    /** {@inheritDoc} */
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = DatatypeHelper.safeTrimOrNullString(request.getParameter(usernameAttribute));
        String password = DatatypeHelper.safeTrimOrNullString(request.getParameter(passwordAttribute));

        if(username == null || password == null){
            redirectToLoginPage(request, response);
            return;
        }
        
        if(authenticateUser(request)){
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
        }else{
            redirectToLoginPage(request, response);
            return;
        }
    }
    
    /**
     * Sends the user to the login page.
     * 
     * @param request current request
     * @param response current response
     */
    protected void redirectToLoginPage(HttpServletRequest request, HttpServletResponse response){
        try {
            StringBuilder pathBuilder = new StringBuilder();
            pathBuilder.append(request.getContextPath());
            pathBuilder.append("/");
            pathBuilder.append(loginPage);

            URLBuilder urlBuilder = new URLBuilder();
            urlBuilder.setScheme(request.getScheme());
            urlBuilder.setHost(request.getLocalName());
            urlBuilder.setPort(request.getLocalPort());
            urlBuilder.setPath(pathBuilder.toString());

            if (log.isDebugEnabled()) {
                log.debug("Redirecting to login page " + urlBuilder.buildURL());
            }

            response.sendRedirect(urlBuilder.buildURL());
            return;
        } catch (IOException ex) {
            log.error("Unable to redirect to login page.", ex);
        }
    }

    /**
     * Authenticate a username and password against JAAS.  If authentication succeeds the principal name and 
     * subject are placed into the request in their respective attributes.
     * 
     * @param request current authentication request
     * 
     * @return true of authentication succeeds, false if not
     */
    protected boolean authenticateUser(HttpServletRequest request) {

        try {
            String username = DatatypeHelper.safeTrimOrNullString(request.getParameter(usernameAttribute));
            String password = DatatypeHelper.safeTrimOrNullString(request.getParameter(passwordAttribute));

            SimpleCallbackHandler cbh = new SimpleCallbackHandler(username, password);

            javax.security.auth.login.LoginContext jaasLoginCtx = new javax.security.auth.login.LoginContext(
                    jaasConfigName, cbh);

            jaasLoginCtx.login();
            log.debug("Successfully authenticated user " + username);
            
            Subject subject = jaasLoginCtx.getSubject();
            Principal principal = subject.getPrincipals().iterator().next();
            request.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, principal.getName());
            request.setAttribute(LoginHandler.SUBJECT_KEY, jaasLoginCtx.getSubject());

            return true;
        } catch (LoginException e) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed", e);
            }
            return false;
        }
    }

    /**
     * A callback handler that provides static name and password data to a JAAS loging process.
     * 
     * This handler only supports {@link NameCallback} and {@link PasswordCallback}.
     */
    protected class SimpleCallbackHandler implements CallbackHandler {

        /** Name of the user. */
        private String uname;

        /** User's password. */
        private String pass;

        /**
         * Constructor.
         * 
         * @param username The username
         * @param password The password
         */
        public SimpleCallbackHandler(String username, String password) {
            uname = username;
            pass = password;
        }

        /**
         * Handle a callback.
         * 
         * @param callbacks The list of callbacks to process.
         * 
         * @throws UnsupportedCallbackException If callbacks has a callback other than {@link NameCallback} or
         *             {@link PasswordCallback}.
         */
        public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {

            if (callbacks == null || callbacks.length == 0) {
                return;
            }

            for (Callback cb : callbacks) {
                if (cb instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) cb;
                    ncb.setName(uname);
                } else if (cb instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) cb;
                    pcb.setPassword(pass.toCharArray());
                }
            }
        }
    }
}