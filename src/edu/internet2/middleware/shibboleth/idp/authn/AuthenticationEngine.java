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

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.common.util.HttpHelper;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;
import edu.internet2.middleware.shibboleth.idp.session.impl.ServiceInformationImpl;

/**
 * Manager responsible for handling authentication requests.
 */
public class AuthenticationEngine extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = 8494202791991613148L;

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationEngine.class);

    /**
     * Gets the manager used to retrieve handlers for requests.
     * 
     * @return manager used to retrieve handlers for requests
     */
    public IdPProfileHandlerManager getProfileHandlerManager() {
        return (IdPProfileHandlerManager) getServletContext().getAttribute("handlerManager");
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
     * Returns control back to the authentication engine.
     * 
     * @param httpRequest current http request
     * @param httpResponse current http response
     */
    public static void returnToAuthenticationEngine(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        LOG.debug("Returning control to authentication engine");
        HttpSession httpSession = httpRequest.getSession();
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (loginContext == null) {
            LOG.error("User HttpSession did not contain a login context.  Unable to return to authentication engine");
        }
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
        LOG.debug("Returning control to profile handler at: {}", loginContext.getProfileHandlerURL());
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
            return;
        } catch (IOException e) {
            LOG.error("Unable to return control back to authentication engine", e);
        } catch (ServletException e) {
            LOG.error("Unable to return control back to authentication engine", e);
        }
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        LOG.debug("Processing incoming request");

        if (httpResponse.isCommitted()) {
            LOG.error("HTTP Response already committed");
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

            AuthenticationMethodInformation authenticationMethod = getUsableExistingAuthenticationMethod(loginContext,
                    shibSession);
            if (authenticationMethod != null) {
                LOG.debug("An active authentication method is applicable for relying party.  Using authentication "
                        + "method {} as authentication method to relying party without re-authenticating user.",
                        authenticationMethod.getAuthenticationMethod());
                authenticateUserWithActiveMethod(httpRequest, httpResponse, authenticationMethod);
                return;
            }

            LOG.debug("No active authentication method is applicable for relying party.  "
                    + "Authenticating user with to be determined method.");
            authenticateUserWithoutActiveMethod1(httpRequest, httpResponse);
        } else {
            LOG.debug("Request returned from authentication handler, completing authentication process.");
            authenticateUserWithoutActiveMethod2(httpRequest, httpResponse);
        }

        return;
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

        LOG.debug("Populating login context with existing session and authentication method information.");
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
    protected void authenticateUserWithoutActiveMethod1(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        HttpSession httpSession = httpRequest.getSession();
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        LOG.debug("Selecting appropriate authentication method for request.");
        Pair<String, LoginHandler> handler = getProfileHandlerManager().getAuthenticationHandler(loginContext);

        if (handler == null) {
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationAttempted();
            loginContext.setAuthenticationFailureMessage("No AuthenticationHandler satisfies the request from: "
                    + loginContext.getRelyingPartyId());
            LOG.error("No AuthenticationHandler satisfies the request from relying party: "
                    + loginContext.getRelyingPartyId());
            returnToProfileHandler(loginContext, httpRequest, httpResponse);
            return;
        }

        LOG.debug("Authentication method {} will be used to authenticate user.", handler.getFirst());
        loginContext.setAuthenticationAttempted();
        loginContext.setAuthenticationDuration(handler.getSecond().getAuthenticationDuration());
        loginContext.setAuthenticationMethod(handler.getFirst());
        loginContext.setAuthenticationEngineURL(HttpHelper.getRequestUriWithoutContext(httpRequest));

        LOG.debug("Transferring control to authentication handler of type: {}", handler.getSecond().getClass()
                .getName());
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
    protected void authenticateUserWithoutActiveMethod2(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        HttpSession httpSession = httpRequest.getSession();

        String principalName = (String) httpRequest.getAttribute(LoginHandler.PRINCIPAL_NAME_KEY);
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (DatatypeHelper.isEmpty(principalName)) {
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailureMessage("No principal name returned from authentication handler.");
            LOG.error("No principal name returned from authentication method: "
                    + loginContext.getAuthenticationMethod());
            returnToProfileHandler(loginContext, httpRequest, httpResponse);
            return;
        }
        loginContext.setPrincipalAuthenticated(true);
        loginContext.setPrincipalName(principalName);
        loginContext.setAuthenticationInstant(new DateTime());

        String shibSessionId = (String) httpSession.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        Session shibSession = getSessionManager().getSession(shibSessionId);

        if (shibSession == null) {
            LOG.debug("Creating shibboleth session for principal {}", principalName);

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

        LOG.debug("Recording authentication and service information in Shibboleth session for principal: {}",
                principalName);
        Subject subject = (Subject) httpRequest.getAttribute(LoginHandler.SUBJECT_KEY);
        String authnMethod = (String) httpRequest.getAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY);
        if (DatatypeHelper.isEmpty(authnMethod)) {
            authnMethod = loginContext.getAuthenticationMethod();
        }

        AuthenticationMethodInformation authnMethodInfo = new AuthenticationMethodInformationImpl(subject, authnMethod,
                new DateTime(), loginContext.getAuthenticationDuration());

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

        if (shibSession == null) {
            return null;
        }

        if (loginContext.getForceAuth()) {
            LOG.debug("Request for forced re-authentication, no existing authentication method considered usable");
            return null;
        }

        List<String> preferredAuthnMethods = loginContext.getRequestedAuthenticationMethods();
        AuthenticationMethodInformation authnMethodInformation = null;
        if (preferredAuthnMethods == null || preferredAuthnMethods.size() == 0) {
            for (AuthenticationMethodInformation info : shibSession.getAuthenticationMethods().values()) {
                if (!info.isExpired()) {
                    authnMethodInformation = info;
                    break;
                }
            }
        } else {
            for (String preferredAuthnMethod : preferredAuthnMethods) {
                if (shibSession.getAuthenticationMethods().containsKey(preferredAuthnMethod)) {
                    AuthenticationMethodInformation info = shibSession.getAuthenticationMethods().get(
                            preferredAuthnMethod);
                    if (!info.isExpired()) {
                        authnMethodInformation = info;
                        break;
                    }
                }
            }
        }

        return authnMethodInformation;
    }
}