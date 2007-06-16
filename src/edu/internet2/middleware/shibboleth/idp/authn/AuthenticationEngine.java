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
import java.net.UnknownHostException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.Pair;

import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;
import edu.internet2.middleware.shibboleth.idp.session.impl.ServiceInformationImpl;

/**
 * Manager responsible for handling authentication requests.
 */
public class AuthenticationEngine extends HttpServlet {

    /** Class logger. */
    private static final Logger LOG = Logger.getLogger(AuthenticationEngine.class);

    /**
     * Gets the manager used to retrieve handlers for requests.
     * 
     * @return manager used to retrieve handlers for requests
     */
    public ProfileHandlerManager getProfileHandlerManager() {
        return (ProfileHandlerManager) getServletContext().getAttribute("handlerManager");
    }

    /**
     * Gets the session manager to be used.
     * 
     * @return session manager to be used
     */
    @SuppressWarnings("unchecked")
    public SessionManager<Session> getSessionManager() {
        return (SessionManager<Session>) getServletContext().getAttribute("sessionManager");
    }

    /**
     * Gets the authentication handler manager used by this engine.
     * 
     * @return authentication handler manager used by this engine
     */
    public AuthenticationHandlerManager getAuthenticationHandlerManager() {
        return (AuthenticationHandlerManager) getServletContext().getAttribute("authenticationHandlerManager");
    }

    /**
     * Returns control back to the authentication engine.
     * 
     * @param httpRequest current http request
     * @param httpResponse current http response
     */
    public static void returnToAuthenticationEngine(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Returning control to authentication engine");
        }
        HttpSession httpSession = httpRequest.getSession();
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        forwardRequest(loginContext.getAuthenticationEngineURL(), httpRequest, httpResponse);
    }

    /**
     * Returns control back to the profile handler that invoked the authentication engine.
     * 
     * @param loginContext current login context
     * @param httpRequest current http request
     * @param httpResponse current http response
     */
    public static void returnToProfileHandler(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Returning control to profile handler at: " + loginContext.getProfileHandlerURL());
        }
        forwardRequest(loginContext.getProfileHandlerURL(), httpRequest, httpResponse);
    }

    /**
     * Forwards a request to the given path.
     * 
     * @param forwardPath path to forward the request to
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected static void forwardRequest(String forwardPath, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        try {
            RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(forwardPath);
            dispatcher.forward(httpRequest, httpResponse);
        } catch (IOException e) {
            LOG.fatal("Unable to return control back to authentication engine", e);
        } catch (ServletException e) {
            LOG.fatal("Unable to return control back to authentication engine", e);
        }
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Processing incoming request");
        }

        HttpSession httpSession = httpRequest.getSession();
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (loginContext == null) {
            LOG.error("Incoming request does not have attached login context");
            throw new ServletException("Incoming request does not have attached login context");
        }

        if (!loginContext.getAuthenticationAttempted()) {
            String shibSessionId = (String) httpSession.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
            Session shibSession = getSessionManager().getSession(shibSessionId);

            if (shibSession != null) {
                AuthenticationMethodInformation authenticationMethod = getUsableExistingAuthenticationMethod(
                        loginContext, shibSession);
                if (authenticationMethod != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("An active authentication method is applicable for relying party.  "
                                + "Using authentication method " + authenticationMethod.getAuthenticationMethod()
                                + " as authentication method to relying party without re-authenticating user.");
                    }
                    authenticateUserWithActiveMethod(httpRequest, httpResponse, authenticationMethod);
                }
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("No active authentication method is applicable for relying party.  "
                        + "Authenticating user with to be determined method.");
            }
            authenticateUserWithoutActiveMethod1(httpRequest, httpResponse);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Request returned from authentication handler, completing authentication process.");
            }
            authenticateUserWithoutActiveMethod2(httpRequest, httpResponse);
        }
    }

    /**
     * Completes the authentication request using an existing, active, authentication method for the current user.
     * 
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     * @param authenticationMethod authentication method to use to complete the request
     */
    protected void authenticateUserWithActiveMethod(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
            AuthenticationMethodInformation authenticationMethod) {
        HttpSession httpSession = httpRequest.getSession();

        String shibSessionId = (String) httpSession.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        Session shibSession = getSessionManager().getSession(shibSessionId);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Populating login context with existing session and authentication method information.");
        }
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        loginContext.setAuthenticationDuration(authenticationMethod.getAuthenticationDuration());
        loginContext.setAuthenticationInstant(authenticationMethod.getAuthenticationInstant());
        loginContext.setAuthenticationMethod(authenticationMethod.getAuthenticationMethod());
        loginContext.setPrincipalAuthenticated(true);
        loginContext.setPrincipalName(shibSession.getPrincipalName());

        ServiceInformation serviceInfo = new ServiceInformationImpl(loginContext.getRelyingPartyId(), new DateTime(),
                authenticationMethod);
        shibSession.getServicesInformation().put(serviceInfo.getEntityID(), serviceInfo);

        returnToProfileHandler(loginContext, httpRequest, httpResponse);
    }

    /**
     * Performs the first part of user authentication. An authentication handler is determined, the login context is
     * populated with some initial information, and control is forward to the selected handler so that it may
     * authenticate the user.
     * 
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void authenticateUserWithoutActiveMethod1(HttpServletRequest httpRequest, 
            HttpServletResponse httpResponse) {
        HttpSession httpSession = httpRequest.getSession();
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Selecting appropriate authentication method for request.");
        }
        Pair<String, AuthenticationHandler> handler = getAuthenticationHandlerManager().getAuthenticationHandler(
                loginContext);

        if (handler == null) {
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailureMessage("No AuthenticationHandler satisfys the request from: "
                            + loginContext.getRelyingPartyId());
            LOG.error("No AuthenticationHandler satisfys the request from relying party: "
                    + loginContext.getRelyingPartyId());
            returnToProfileHandler(loginContext, httpRequest, httpResponse);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authentication method " + handler.getFirst() + " will be used to authenticate user.");
        }
        loginContext.setAuthenticationAttempted();
        loginContext.setAuthenticationDuration(handler.getSecond().getAuthenticationDuration());
        loginContext.setAuthenticationMethod(handler.getFirst());
        loginContext.setAuthenticationEngineURL(httpRequest.getRequestURI());

        if (LOG.isDebugEnabled()) {
            LOG.debug("Transferring control to authentication handler of type: "
                    + handler.getSecond().getClass().getName());
        }
        handler.getSecond().login(httpRequest, httpResponse);
    }

    /**
     * Performs the second part of user authentication. The principal name set by the authentication handler is
     * retrieved and pushed in to the login context, a Shibboleth session is created if needed, information indicating
     * that the user has logged into the service is recorded and finally control is returned back to the profile
     * handler.
     * 
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void authenticateUserWithoutActiveMethod2(HttpServletRequest httpRequest, 
            HttpServletResponse httpResponse) {
        HttpSession httpSession = httpRequest.getSession();

        String principalName = (String) httpRequest.getAttribute(AuthenticationHandler.PRINCIPAL_NAME_KEY);
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (DatatypeHelper.isEmpty(principalName)) {
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailureMessage("No principal name returned from authentication handler.");
            LOG.error("No principal name returned from authentication method: "
                    + loginContext.getAuthenticationMethod());
            returnToProfileHandler(loginContext, httpRequest, httpResponse);
        }
        loginContext.setPrincipalName(principalName);

        String shibSessionId = (String) httpSession.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        Session shibSession = getSessionManager().getSession(shibSessionId);

        if (shibSession == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Creating shibboleth session for principal " + principalName);
            }

            InetAddress addr;
            try {
                addr = InetAddress.getByName(httpRequest.getRemoteAddr());
            } catch (UnknownHostException ex) {
                addr = null;
            }

            shibSession = (Session) getSessionManager().createSession(addr, loginContext.getPrincipalName());
            loginContext.setSessionID(shibSession.getSessionID());
            httpSession.setAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE, shibSession.getSessionID());
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Recording authentication and service information in Shibboleth session for principal: "
                    + principalName);
        }
        AuthenticationMethodInformation authnMethodInfo = new AuthenticationMethodInformationImpl(loginContext
                .getAuthenticationMethod(), new DateTime(), loginContext.getAuthenticationDuration());
        shibSession.getAuthenticationMethods().put(authnMethodInfo.getAuthenticationMethod(), authnMethodInfo);

        ServiceInformation serviceInfo = new ServiceInformationImpl(loginContext.getRelyingPartyId(), new DateTime(),
                authnMethodInfo);
        shibSession.getServicesInformation().put(serviceInfo.getEntityID(), serviceInfo);

        shibSession.setLastActivityInstant(new DateTime());

        returnToProfileHandler(loginContext, httpRequest, httpResponse);
    }

    /**
     * Gets the authentication method, currently active for the user, that also meets the requirements expressed by the
     * login context. If a method is returned the user does not need to authenticate again, if null is returned then the
     * user must be authenticated.
     * 
     * @param loginContext user login context
     * @param shibSession user's shibboleth session
     * 
     * @return active authentication method that meets authentication requirements or null
     */
    protected AuthenticationMethodInformation getUsableExistingAuthenticationMethod(LoginContext loginContext,
            Session shibSession) {
        if (loginContext.getForceAuth() || shibSession == null) {
            return null;
        }

        List<String> preferredAuthnMethods = loginContext.getRequestedAuthenticationMethods();

        if (preferredAuthnMethods == null || preferredAuthnMethods.size() == 0) {
            for (AuthenticationMethodInformation authnMethod : shibSession.getAuthenticationMethods().values()) {
                if (!authnMethod.isExpired()) {
                    return authnMethod;
                }
            }
        } else {
            for (String preferredAuthnMethod : preferredAuthnMethods) {
                if (shibSession.getAuthenticationMethods().containsKey(preferredAuthnMethod)) {
                    AuthenticationMethodInformation authnMethodInfo = shibSession.getAuthenticationMethods().get(
                            preferredAuthnMethod);
                    if (!authnMethodInfo.isExpired()) {
                        return authnMethodInfo;
                    }
                }
            }
        }

        return null;
    }
}