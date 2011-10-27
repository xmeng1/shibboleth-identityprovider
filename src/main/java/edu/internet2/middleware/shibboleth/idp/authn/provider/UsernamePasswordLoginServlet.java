/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;

/**
 * This Servlet authenticates a user via JAAS. The user's credential is always added to the returned {@link Subject} as
 * a {@link UsernamePasswordCredential} within the subject's private credentials.
 * 
 * By default, this Servlet assumes that the authentication method {@value AuthnContext#PPT_AUTHN_CTX} to be returned to
 * the authentication engine. This can be override by setting the servlet configuration parameter
 * {@value LoginHandler#AUTHENTICATION_METHOD_KEY}.
 */
public class UsernamePasswordLoginServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -572799841125956990L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(UsernamePasswordLoginServlet.class);
    
    /** The authentication method returned to the authentication engine. */
    private String authenticationMethod;

    /** Name of JAAS configuration used to authenticate users. */
    private String jaasConfigName = "ShibUserPassAuth";

    /** init-param which can be passed to the servlet to override the default JAAS config. */
    private final String jaasInitParam = "jaasConfigName";

    /** Login page name. */
    private String loginPage = "login.jsp";

    /** init-param which can be passed to the servlet to override the default login page. */
    private final String loginPageInitParam = "loginPage";

    /** Parameter name to indicate login failure. */
    private final String failureParam = "loginFailed";

    /** HTTP request parameter containing the user name. */
    private final String usernameAttribute = "j_username";

    /** HTTP request parameter containing the user's password. */
    private final String passwordAttribute = "j_password";

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        if (getInitParameter(jaasInitParam) != null) {
            jaasConfigName = getInitParameter(jaasInitParam);
        }

        if (getInitParameter(loginPageInitParam) != null) {
            loginPage = getInitParameter(loginPageInitParam);
        }
        if (!loginPage.startsWith("/")) {
            loginPage = "/" + loginPage;
        }
        
        String method =
                DatatypeHelper.safeTrimOrNullString(config.getInitParameter(LoginHandler.AUTHENTICATION_METHOD_KEY));
        if (method != null) {
            authenticationMethod = method;
        } else {
            authenticationMethod = AuthnContext.PPT_AUTHN_CTX;
        }
    }

    /** {@inheritDoc} */
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {
        String username = request.getParameter(usernameAttribute);
        String password = request.getParameter(passwordAttribute);

        if (username == null || password == null) {
            redirectToLoginPage(request, response);
            return;
        }

        try {
            authenticateUser(request, username, password);
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
        } catch (LoginException e) {
            request.setAttribute(failureParam, "true");
            request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, new AuthenticationException(e));
            redirectToLoginPage(request, response);
        }
    }

    /**
     * Sends the user to the login page.
     * 
     * @param request current request
     * @param response current response
     */
    protected void redirectToLoginPage(HttpServletRequest request, HttpServletResponse response) {

        StringBuilder actionUrlBuilder = new StringBuilder();
        if(!"".equals(request.getContextPath())){
            actionUrlBuilder.append(request.getContextPath());
        }
        actionUrlBuilder.append(request.getServletPath());
        
        request.setAttribute("actionUrl", actionUrlBuilder.toString());

        try {
            request.getRequestDispatcher(loginPage).forward(request, response);
            log.debug("Redirecting to login page {}", loginPage);
        } catch (IOException ex) {
            log.error("Unable to redirect to login page.", ex);
        } catch (ServletException ex) {
            log.error("Unable to redirect to login page.", ex);
        }
    }

    /**
     * Authenticate a username and password against JAAS. If authentication succeeds the name of the first principal, or
     * the username if that is empty, and the subject are placed into the request in their respective attributes.
     * 
     * @param request current authentication request
     * @param username the principal name of the user to be authenticated
     * @param password the password of the user to be authenticated
     * 
     * @throws LoginException thrown if there is a problem authenticating the user
     */
    protected void authenticateUser(HttpServletRequest request, String username, String password) throws LoginException {
        try {
            log.debug("Attempting to authenticate user {}", username);

            SimpleCallbackHandler cbh = new SimpleCallbackHandler(username, password);

            javax.security.auth.login.LoginContext jaasLoginCtx = new javax.security.auth.login.LoginContext(
                    jaasConfigName, cbh);

            jaasLoginCtx.login();
            log.debug("Successfully authenticated user {}", username);

            Subject loginSubject = jaasLoginCtx.getSubject();

            Set<Principal> principals = loginSubject.getPrincipals();
            principals.add(new UsernamePrincipal(username));

            Set<Object> publicCredentials = loginSubject.getPublicCredentials();

            Set<Object> privateCredentials = loginSubject.getPrivateCredentials();
            privateCredentials.add(new UsernamePasswordCredential(username, password));

            Subject userSubject = new Subject(false, principals, publicCredentials, privateCredentials);
            request.setAttribute(LoginHandler.SUBJECT_KEY, userSubject);
            request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);
        } catch (LoginException e) {
            log.debug("User authentication for " + username + " failed", e);
            throw e;
        } catch (Throwable e) {
            log.debug("User authentication for " + username + " failed", e);
            throw new LoginException("unknown authentication error");
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