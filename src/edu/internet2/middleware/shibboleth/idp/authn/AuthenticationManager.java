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

import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;
import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.session.SessionManager;

import javolution.util.FastList;
import javolution.util.FastMap;

import org.apache.log4j.Logger;

import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.RequestedAuthnContext;

import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.RequestedAuthnContext;

import org.springframework.web.servlet.HttpServletBean;


/**
 * Manager responsible for handling authentication requests.
 */
public class AuthenticationManager extends HttpServletBean {
    
    private static final Logger log =
	    Logger.getLogger(AuthenticationManager.class.getName());
    
    /** SessionManager to be used */
    private SessionManager sessionMgr;
    
    /** Map of URIs onto AuthenticationHandlerInfo */
    private FastMap<String, AuthenticationHandler> handlerMap
	    = new FastMap<String, AuthenticationHandler>();
    
    /** The default AuthenticationHandler */
    private AuthenticationHandler defaultHandler;
    
    /* The URI for the default AuthenticationHandler */
    private String defaultHandlerURI;

	    
    /**
     * Gets the session manager to be used
     *
     * @return session manager to be used
     */
    public SessionManager getSessionManager() {
	return this.sessionMgr;
    }
    
    
    /**
     * Sets the session manager to be used.
     *
     * @param manager session manager to be used.
     */
    public void setSessionManager(final SessionManager manager) {
	this.sessionMgr = manager;
    }
    
    
    /**
     * Add a <String:AuthenticationHandler> mapping to the
     * AuthenticationManager's table. If a mapping for the URI
     * already exists, it will be overwritten.
     *
     * The URI SHOULD be from the saml-autn-context-2.0-os
     *
     * @param uri A URI identifying the authentcation method.
     * @param handlerInfo Informarmation about the handler.
     *
     * @throws IllegalArgumentExcetption if <code>handlerInfo.getUri()</code> returns </code>null</code>
     */
    public void addHandlerMapping(String uri, AuthenticationHandler handler) {
	
	if (uri == null || handler == null) {
	    return;
	}
	
	log.debug("registering " + handler.getClass().getName()
	    + " for " + uri);
	
	this.handlerMap.put(uri, handler);
    }
    
    
    /**
     * Register the default {@link AuthenticationHandler}
     *
     * @param uri The URI of the default authentication handler (from saml-authn-context-2.0-os)
     * @param handler The default {@link AuthenticationHandler}.
     */
    public void addDefaultHandler(String uri, AuthenticationHandler handler) {
	
	log.debug("Registering default handler "
		+ handler.getClass().getName());
	
	this.defaultHandler = handler;
	this.defaultHandlerURI = uri;
    }
    
    
    /**
     * Remove a <String:AuthenticationHandler> mapping from the
     * AuthenticationManager's table.
     *
     * The URI SHOULD be from the saml-authn-context-2.0-os
     *
     * @param uri A URI identifying the authentcation method.
     */
    public void removeHandlerMapping(String uri) {
	
	if (uri == null) {
	    return;
	}
	
	log.debug("unregistering handler for " + uri);
	
	this.handlerMap.remove(uri);
    }
    
    
    
    /**
     * Primary entrypoint for the AuthnManager
     */
    public void doPost(HttpServletRequest req,
	    HttpServletResponse resp) throws ServletException, IOException {
	
	if (req == null || resp == null) {
	    log.error("Invalid parameters in AuthenticationManager's doPost().");
	    return;
	}
	
	HttpSession httpSession = req.getSession();
	if (httpSession == null) {
	    log.error("Unable to retrieve HttpSession from request.");
	    return;
	}
	Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
	if (! (o instanceof LoginContext)) {
	    log.error("Invalid login context object -- object is not an instance of LoginContext.");
	    return;
	}
	LoginContext loginContext = (LoginContext)o;
	
	// If authentication has been attempted, don't try it again.
	if (loginContext.getAuthenticationAttempted()) {
	    this.handleNewAuthnRequest(loginContext, req, resp);
	} else {
	    this.finishAuthnRequest(loginContext, req, resp);
	}
	
	
    }
    
    
    
    /**
     * Handle a new {@link AuthnRequest}s
     *
     */
    private void handleNewAuthnRequest(final LoginContext loginContext,
	    final HttpServletRequest servletRequest,
	    final HttpServletResponse servletResponse) throws ServletException, IOException {
	
	boolean forceAuthN = loginContext.getForceAuth();
	boolean isPassive = loginContext.getPassiveAuth();
	
	RequestedAuthnContext authnCtx = null;
	
	// if loginContext is really a Saml2LoginContext, extract the
	// (possibly null) RequestedAuthnContext.
	if (loginContext instanceof Saml2LoginContext) {
	    Saml2LoginContext samlLoginContext = (Saml2LoginContext)loginContext;
	    authnCtx = samlLoginContext.getRequestedAuthnContext();
	}
	
	// if no registered handler can evaluate the request, abort.
	AuthenticationHandler handler =
		this.getHandler(authnCtx, loginContext, forceAuthN, isPassive);
	if (handler == null) {
	    loginContext.setAuthenticationAttempted();
	    loginContext.setAuthenticationOK(false);
	    loginContext.setAuthenticationFailureMessage("No installed AuthenticationHandlers can satisfy the authentication request.");
	    
	    RequestDispatcher dispatcher =
		    servletRequest.getRequestDispatcher(loginContext.getProfileHandlerURL());
	    dispatcher.forward(servletRequest, servletResponse);
	}
	
	// otherwise, forward control to the authenticationhandler
	ServletContext servletContext = this.getServletContext();
	loginContext.setAuthenticationManagerURL(servletRequest.getPathInfo());
	handler.setReturnLocation(servletRequest.getPathInfo());
	handler.login(servletRequest, servletResponse,
		loginContext.getPassiveAuth(), loginContext.getForceAuth());
    }
    
    
    /**
     * Handle the "return leg" of an authentication request
     * (i.e. clean up after an authentication handler has run).
     *
     */
    private void finishAuthnRequest(final LoginContext loginContext,
	    final HttpServletRequest servletRequest,
	    final HttpServletResponse servletResponse) throws ServletException, IOException {
	
	// if authentication was successful, the authentication handler should
	// have updated the LoginContext with additional information. Use that
	// info to create a Session.
	if (loginContext.getAuthenticationOK()) {
	    
	    AuthenticationMethodInformationImpl authMethodInfo =
		    new AuthenticationMethodInformationImpl(loginContext.getAuthenticationMethod(),
			loginContext.getAuthenticationInstant(), loginContext.getAuthenticationDuration());
	    
	    Session shibSession = this.getSessionManager().createSession();
	    List<AuthenticationMethodInformation> authMethods = shibSession.getAuthenticationMethods();
	    authMethods.add(authMethodInfo);
	    loginContext.setSessionID(shibSession.getSessionID());
	}
	
	RequestDispatcher dispatcher =
		servletRequest.getRequestDispatcher(loginContext.getProfileHandlerURL());
	dispatcher.forward(servletRequest, servletResponse);
    }
    
    
    /**
     * "Stub" method for handling LogoutRequest
     */
    private void handleLogoutRequest(final HttpServletRequest servletRequest,
	    final HttpServletResponse servletResponse) throws ServletException, IOException {
	
    }
    
    
    /**
     * Examine an {@link RequestedAuthnContext} against a list of installed
     * {@link AuthenticationHandler}s. If an acceptable handler is found, return
     * a reference to it. Otherwise return <code>null</code>. The {@link LoginContext}
     * is updated to reflect the selected authentication method's URI.
     *
     * @param authnCtx A {@link RequestedAuthnContext}
     * @param loginCtx The {@link LoginContext} 
     * @param forceAuthN Should authentication be forced.
     * @param passiveAuthN Must authentication happen without UI control.
     *
     * @return A reference to an {@link AuthenticationHandler} or <code>null</code>.
     */
    private AuthenticationHandler getHandler(final RequestedAuthnContext authnCtx,
	    final LoginContext loginCtx, boolean forceAuthN, boolean passiveAuthN) {
	
	// if no context is specified, evaluate the default handler
	if (authnCtx == null) {
	    loginCtx.setAuthenticationMethod(this.defaultHandlerURI);
	    return this.evaluateHandler(this.defaultHandler, "default", 
		    forceAuthN, passiveAuthN);
	}
	
	
	// For the immediate future, we only support the "exact" comparator.
	AuthnContextComparisonTypeEnumeration comparator = authnCtx.getComparison();
	if (comparator != null && comparator != AuthnContextComparisonTypeEnumeration.EXACT) {
	    log.error("Unsupported comparision operator ( " + comparator
		    + ") in RequestedAuthnContext. Only exact comparisions are supported.");
	    return (null);
	}
	
	// build a list of all requested authn classes and declrefs
	List<String> requestedAuthnMethods = new FastList<String>();
	List<AuthnContextClassRef> authnClasses = authnCtx.getAuthnContextClassRefs();
	List<AuthnContextDeclRef> authnDeclRefs = authnCtx.getAuthnContextDeclRefs();
	
	if (authnClasses != null) {
	    for (AuthnContextClassRef classRef : authnClasses) {
		if (classRef != null) {
		    String s = classRef.getAuthnContextClassRef();
		    if (s != null) {
			requestedAuthnMethods.add(s);
		    }
		}
	    }
	}
	
	if (authnDeclRefs != null) {
	    for (AuthnContextDeclRef declRef : authnDeclRefs) {
		if (declRef != null) {
		    String s = declRef.getAuthnContextDeclRef();
		    if (s != null) {
			requestedAuthnMethods.add(s);
		    }
		}
	    }
	}
	
	
	// if no AuthnContextClasses or AuthnContextDeclRefs were actually specified,
	// evaluate the default handler
	if (requestedAuthnMethods.size() == 0) {
	    return this.evaluateHandler(this.defaultHandler, "default",
		    forceAuthN, passiveAuthN);
	}
	
	
	// evaluate all requested authn methods until we find a match.
	AuthenticationHandler handler = null;
	for (String s : requestedAuthnMethods) {
	    
	    AuthenticationHandler candidateHandler = this.handlerMap.get(s);
	    if (candidateHandler == null) {
		log.debug("No registered authentication handlers can satisfy the "
			+ " requested authentication method " + s);
		continue;
	    }
	    
	    handler = this.evaluateHandler(candidateHandler, s, forceAuthN, passiveAuthN);
	    
	    if (handler != null) {
		// we found a match. stop iterating.
		log.info("Using authentication handler " + handler.getClass().getName()
		    + " for authentication method " + s);
		loginCtx.setAuthenticationMethod(s);
		break;
	    }
	}
	
	if (handler == null) {
	    log.error("No registered authentication handlers could satisify any requested "
		    + "authentication methods. Unable to process authentication request.");
	}
	
	return (handler);
    }
    
    
    /**
     * Evaluate an authenticationhandler against a set of evaluation criteria.
     *
     * @param handler A candiate {@link AuthenticationHandler}
     * @param description A description of the handler
     * @param forceAuthN Is (re)authentication forced?
     * @param passiveAuthN Can the AuthenticationHandler take control of the UI
     * @return A reference to an {@link AuthenticationHandler} or <code>null</code>.
     */
    private AuthenticationHandler evaluateHandler(final AuthenticationHandler handler,
	    String description, boolean forceAuthN, boolean passiveAuthN) {
	
	if (handler == null) {
	    return (null);
	}
	
	if (forceAuthN && !handler.supportsForceAuthentication()) {
	    log.debug("The RequestedAuthnContext required forced authentication, "
		    + "but the " + description + " handler does not support that feature.");
	    return (null);
	}
	
	if (passiveAuthN && !handler.supportsPassive()) {
	    log.debug("The RequestedAuthnContext required passive authentication, "
		    + "but the " + description + " handler does not support that feature.");
	    return (null);
	}
	
	return handler;
    }
}
