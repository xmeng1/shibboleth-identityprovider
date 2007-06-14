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

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

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
 * This servlet should be protected by a filter which populates REMOTE_USER. The
 * serlvet will then set the remote user field in a LoginContext.
 */
public class UsernamePasswordAuthenticationServlet extends HttpServlet {

	// Implementation note:
	// Pay attention to namespaces in this file. There are two classes named
	// LoginContext.
	// One is used by the IdP
	// (edu.internet2.middleware.shibboleth.idp.authn.LoginContext).
	// The other is used by JAAS (javax.security.auth.login.LoginContext).
	//

	/**
	 * Inner class to hold the username and password.
	 * 
	 * The web form will give us a username and password. We call out to a JAAS
	 * mechanism(s) to authenticate the user. This inner class implements the
	 * {@link CallbackHandler} interface to deliver the username and password to
	 * a JAAS {@link LoginModule}.
	 * 
	 * Note, this class only handles the {@link NameCallback} and
	 * {@link PasswordCallback}.
	 */
	protected class SimpleCallbackHandler implements CallbackHandler {

		private String uname;

		private String pass;

		/**
		 * @param username
		 *            The username
		 * @param password
		 *            The password
		 */
		public SimpleCallbackHandler(String username, String password) {
			uname = username;
			pass = password;
		}

		/**
		 * Handle a callback.
		 * 
		 * @param callbacks
		 *            The list of callbacks to process.
		 * 
		 * @throws UnsupportedCallbackException
		 *             If callbacks has a callback other than
		 *             {@link NameCallback} or {@link PasswordCallback}.
		 */
		public void handle(final Callback[] callbacks)
				throws UnsupportedCallbackException {

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
				} else {
					throw new UnsupportedCallbackException(cb,
							"This class only handles NameCallback and PasswordCallback");
				}
			}
		}
	}

	/** Login form element containing the username. */
	protected static final String LOGIN_FORM_USERNAME = "username";

	/** Login form element containing the password. */
	protected static final String LOGIN_FORM_PASSWORD = "password";

	private static final Logger log = Logger
			.getLogger(RemoteUserAuthServlet.class);

	public UsernamePasswordAuthenticationServlet() {
	}

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        
        HttpSession httpSession = request.getSession();
        
        Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (!(o instanceof LoginContext)) {
            log.error("RemoteUSerAuthServlet - Invalid login context object -- object is not an instance of LoginContext");
            return; // where this will return to, I don't know.
        }
        
        LoginContext loginContext = (LoginContext)o;
        
        o = httpSession.getAttribute(UsernamePasswordAuthenticationHandler.JAAS_CONFIG_NAME);
        httpSession.removeAttribute(UsernamePasswordAuthenticationHandler.JAAS_CONFIG_NAME);
        if (!(o instanceof String)) {
            log.error("UsernamePasswordAuthenticationServlet: Unable to authenticate user - Invalid JAAS configuration name specified: " + o.toString());
            
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailureMessage("Internal configuration error.");
            redirectControl(loginContext.getAuthenticationManagerURL(), "AuthenticationManager", request, response);
        }
        
        String jassConfiguration = (String)o;
        
        String username;
        String password;
        
        o = request.getAttribute(LOGIN_FORM_USERNAME);
        if (!(o instanceof String)) {
            log.error("UsernamePasswordAuthenticationServlet: Login form's username is not a String.");
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailureMessage("Internal configuration error.");
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailureMessage("Internal configuration error.");
            redirectControl(loginContext.getAuthenticationManagerURL(), "AuthenticationManager", request, response);
            
        }
        username = (String)o;
        
        o = request.getAttribute(LOGIN_FORM_PASSWORD);
        if (!(o instanceof String)) {
            log.error("UsernamePasswordAuthenticationServlet: Login form's password is not a String.");
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailureMessage("Internal configuration error.");
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailureMessage("Internal configuration error.");
            redirectControl(loginContext.getAuthenticationManagerURL(), "AuthenticationManager", request, response);
            
        }
        password = (String)o;
        
        authenticateUser(username, password, jassConfiguration, loginContext);
        password = null;
        redirectControl(loginContext.getAuthenticationManagerURL(), "AuthenticationManager", request, response);
    }

	/**
	 * Return control to the AuthNManager.
	 * 
	 * @param url
	 *            The URL to which control should be redirected.
	 * @param urlDescription
	 *            An optional textual description of <code>url</code>.
	 * @param request
	 *            The HttpServletRequest.
	 * @param response
	 *            The HttpServletResponse.
	 */
	protected void redirectControl(String url, String urlDescription,
			final HttpServletRequest request, final HttpServletResponse response) {

		try {
			RequestDispatcher dispatcher = request.getRequestDispatcher(url);
			dispatcher.forward(request, response);
		} catch (ServletException ex) {
			log.error(
					"UsernamePasswordAuthenticationServlet: Error returning control to "
							+ urlDescription, ex);
		} catch (IOException ex) {
			log.error(
					"UsernamePasswordAuthenticationServlet: Error returning control to "
							+ urlDescription, ex);
		}
	}

	/**
	 * Authenticate a username and password against JAAS.
	 * 
	 * @param username
	 *            The username
	 * @param password
	 *            The password.
	 * @param jaasConfigurationName
	 *            The name of the JAAS configuration entry.
	 * @param idpLoginCtx
	 *            The authentication request's LoginContext
	 */
	protected void authenticateUser(
			String username,
			String password,
			String jaasConfigurationName,
			final edu.internet2.middleware.shibboleth.idp.authn.LoginContext idpLoginCtx) {

		try {
			SimpleCallbackHandler cbh = new SimpleCallbackHandler(username,
					password);

			javax.security.auth.login.LoginContext jaasLoginCtx = new javax.security.auth.login.LoginContext(
					jaasConfigurationName, cbh);

			idpLoginCtx.setAuthenticationAttempted();
			idpLoginCtx.setAuthenticationInstant(new DateTime());

			jaasLoginCtx.login();
			log
					.debug("UsernamePasswordAuthenticationServlet: Authentication successful for "
							+ username);
			idpLoginCtx.setPrincipalAuthenticated(true);

			// if JAAS returned multiple usernames, only use the first one.
			Set<Principal> principals = jaasLoginCtx.getSubject()
					.getPrincipals();
			Principal[] temp = new Principal[principals.size()];
			principals.toArray(temp);
			idpLoginCtx.setPrincipalName(temp[0].getName());

		} catch (LoginException ex) {
			log
					.error(
							"UsernamePasswordAuthenticationServlet: Error authenticating user.",
							ex);
			idpLoginCtx.setPrincipalAuthenticated(false);
		}
	}
}
