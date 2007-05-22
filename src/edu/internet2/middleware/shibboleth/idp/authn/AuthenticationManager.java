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

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javolution.util.FastMap;

import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;

import org.apache.log4j.Logger;
import org.springframework.web.servlet.HttpServletBean;

/**
 * Manager responsible for handling authentication requests.
 */
public class AuthenticationManager extends HttpServletBean {

	/** log4j. */
	private static final Logger log = Logger.getLogger(AuthenticationManager.class);

	/** SessionManager to be used. */
	private SessionManager sessionMgr;

	/** Map of URIs onto AuthenticationHandlerInfo. */
	private Map<String, AuthenticationHandler> handlerMap = new ConcurrentHashMap<String, AuthenticationHandler>();

	/** The default AuthenticationHandler. */
	private AuthenticationHandler defaultHandler;

	/* The URI for the default AuthenticationHandler. */
	private String defaultHandlerURI;

	/**
	 * Gets the session manager to be used.
	 * 
	 * @return session manager to be used
	 */
	public SessionManager getSessionManager() {
		return sessionMgr;
	}

	/**
	 * Sets the session manager to be used.
	 * 
	 * @param manager
	 *            session manager to be used.
	 */
	public void setSessionManager(final SessionManager manager) {
		sessionMgr = manager;
	}

	/**
	 * Get the map of {@link AuthenticationHandlers}.
	 * 
	 * @return The map of AuthenticationHandlers
	 */
	public Map<String, AuthenticationHandler> getHandlerMap() {

		return new FastMap<String, AuthenticationHandler>(handlerMap);
	}

	/**
	 * Set the {@link AuthenticationHandler} map.
	 * 
	 * @param handlerMap
	 *            The Map of URIs to AuthenticationHandlers
	 */
	public void setHandlerMap(
			final Map<String, AuthenticationHandler> handlerMap) {

		for (String uri : handlerMap.keySet()) {
			addHandlerMapping(uri, handlerMap.get(uri));
		}
	}

	/**
	 * Add a <code>&lt;String:AuthenticationHandler&gr;</code> mapping to the
	 * AuthenticationManager's table. If a mapping for the URI already exists,
	 * it will be overwritten.
	 * 
	 * The URI SHOULD be from the saml-autn-context-2.0-os
	 * 
	 * @param uri
	 *            A URI identifying the authentcation method.
	 * @param handler
	 *            The AuthenticationHandler.
	 */
	public void addHandlerMapping(String uri, AuthenticationHandler handler) {

		if (uri == null || handler == null) {
			return;
		}

		log
				.debug("registering " + handler.getClass().getName() + " for "
						+ uri);

		handlerMap.put(uri, handler);
	}

	/**
	 * Register the default {@link AuthenticationHandler}.
	 * 
	 * @param uri
	 *            The URI of the default authentication handler (from
	 *            saml-authn-context-2.0-os)
	 * @param handler
	 *            The default {@link AuthenticationHandler}.
	 */
	public void setDefaultHandler(String uri, AuthenticationHandler handler) {

		log.debug("Registering default handler "
						+ handler.getClass().getName());

		defaultHandler = handler;
		defaultHandlerURI = uri;
	}

	/**
	 * Remove a <String:AuthenticationHandler> mapping from the
	 * AuthenticationManager's table.
	 * 
	 * The URI SHOULD be from the saml-authn-context-2.0-os
	 * 
	 * @param uri
	 *            A URI identifying the authentcation method.
	 */
	public void removeHandlerMapping(String uri) {

		if (uri == null) {
			return;
		}

		log.debug("unregistering handler for " + uri);

		handlerMap.remove(uri);
	}

	/**
	 * Primary entrypoint for the AuthnManager.
	 * 
	 * @param req
	 *            The ServletRequest.
	 * @param resp
	 *            The ServletResponse.
	 */
	public void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {

		if (req == null || resp == null) {
			log
					.error("Invalid parameters in AuthenticationManager's doPost().");
			return;
		}

		HttpSession httpSession = req.getSession();
		Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
		if (!(o instanceof LoginContext)) {
			log
					.error("Invalid login context object -- object is not an instance of LoginContext.");
			return;
		}
		LoginContext loginContext = (LoginContext) o;

		// If authentication has been attempted, don't try it again.
		if (loginContext.getAuthenticationAttempted()) {
			handleNewAuthnRequest(loginContext, req, resp);
		} else {
			finishAuthnRequest(loginContext, req, resp);
		}
	}

	/**
	 * Handle a new authentication request.
	 * 
	 * @param loginContext
	 *            The {@link LoginContext} for the new authentication request
	 * @param servletRequest
	 *            The servlet request containing the authn request
	 * @param servletResponse
	 *            The associated servlet response.
	 */
	private void handleNewAuthnRequest(final LoginContext loginContext,
			final HttpServletRequest servletRequest,
			final HttpServletResponse servletResponse) throws ServletException,
			IOException {

		boolean forceAuthN = loginContext.getForceAuth();
		boolean passiveAuthN = loginContext.getPassiveAuth();

		// set that authentication has been attempted, to prevent processing
		// loops
		loginContext.setAuthenticationAttempted();

		// if the profile handler set a list of requested authn methods,
		// evaluate them. otherwise, evaluate the default handler.
		String[] requestedAuthnMethods = loginContext
				.getRequestedAuthenticationMethods();
		AuthenticationHandler handler = null;

		if (requestedAuthnMethods == null) {

			// if no authn methods were specified, try the default handler

			if (evaluateHandler(defaultHandler, "default", forceAuthN,
					passiveAuthN)) {
				handler = defaultHandler;
				loginContext.setAuthenticationMethod(defaultHandlerURI);
			}

		} else {

			// evaluate all requested authn methods until we find a match.

			for (String authnMethodURI : requestedAuthnMethods) {

				AuthenticationHandler candidateHandler = handlerMap
						.get(authnMethodURI);
				if (candidateHandler == null) {
					log
							.debug("No registered authentication handlers can satisfy the "
									+ " requested authentication method "
									+ authnMethodURI);
					continue;
				}

				if (evaluateHandler(candidateHandler, authnMethodURI,
						forceAuthN, passiveAuthN)) {

					// we found a match. stop iterating.
					handler = candidateHandler;
					log.info("Using authentication handler "
							+ handler.getClass().getName()
							+ " for authentication method " + authnMethodURI);
					loginContext.setAuthenticationMethod(authnMethodURI);
					break;
				}
			}
		}

		// if no acceptable handler was found, abort.
		if (handler == null) {
			loginContext.setAuthenticationOK(false);
			loginContext
					.setAuthenticationFailureMessage("No installed AuthenticationHandler can satisfy the authentication request.");

			log
					.error("No registered authentication handlers could satisify any requested "
							+ "authentication methods. Unable to process authentication request.");

			RequestDispatcher dispatcher = servletRequest
					.getRequestDispatcher(loginContext.getProfileHandlerURL());
			dispatcher.forward(servletRequest, servletResponse);
		}

		// otherwise, forward control to the AuthenticationHandler
		loginContext.setAuthenticationManagerURL(servletRequest.getRequestURI());
		handler.login(servletRequest, servletResponse, loginContext);
	}

	/**
	 * Handle the "return leg" of an authentication request (i.e. clean up after
	 * an authentication handler has run).
	 * 
	 */
	private void finishAuthnRequest(final LoginContext loginContext,
			final HttpServletRequest servletRequest,
			final HttpServletResponse servletResponse) throws ServletException,
			IOException {

		// if authentication was successful, the authentication handler should
		// have updated the LoginContext with additional information. Use that
		// info to create a Session.
		if (loginContext.getAuthenticationOK()) {

			AuthenticationMethodInformation authMethodInfo = new AuthenticationMethodInformationImpl(
					loginContext.getAuthenticationMethod(), loginContext
							.getAuthenticationInstant(), loginContext
							.getAuthenticationDuration());

			InetAddress addr;
			try {
				addr = InetAddress.getByName(servletRequest.getRemoteAddr());
			} catch (Exception ex) {
				addr = null;
			}

			Session shibSession = (Session) sessionMgr.createSession(addr,
					loginContext.getUserID());
			List<AuthenticationMethodInformation> authMethods = shibSession
					.getAuthenticationMethods();
			authMethods.add(authMethodInfo);
			loginContext.setSessionID(shibSession.getSessionID());
		}

		RequestDispatcher dispatcher = servletRequest
				.getRequestDispatcher(loginContext.getProfileHandlerURL());
		dispatcher.forward(servletRequest, servletResponse);
	}

	/**
	 * "Stub" method for handling LogoutRequest.
	 */
	private void handleLogoutRequest(final HttpServletRequest servletRequest,
			final HttpServletResponse servletResponse) throws ServletException,
			IOException {

	}

	/**
	 * Evaluate an authenticationhandler against a set of evaluation criteria.
	 * 
	 * @param handler
	 *            A candiate {@link AuthenticationHandler}
	 * @param description
	 *            A description of the handler
	 * @param forceAuthN
	 *            Is (re)authentication forced?
	 * @param passiveAuthN
	 *            Can the AuthenticationHandler take control of the UI
	 * 
	 * @return <code>true</code> if handler meets the criteria, otherwise
	 *         <code>false</code>
	 */
	private boolean evaluateHandler(final AuthenticationHandler handler,
			String description, boolean forceAuthN, boolean passiveAuthN) {

		if (handler == null) {
			return false;
		}

		if (forceAuthN && !handler.supportsForceAuthentication()) {
			log
					.debug("The RequestedAuthnContext required forced authentication, "
							+ "but the "
							+ description
							+ " handler does not support that feature.");
			return false;
		}

		if (passiveAuthN && !handler.supportsPassive()) {
			log
					.debug("The RequestedAuthnContext required passive authentication, "
							+ "but the "
							+ description
							+ " handler does not support that feature.");
			return false;
		}

		return true;
	}
}
