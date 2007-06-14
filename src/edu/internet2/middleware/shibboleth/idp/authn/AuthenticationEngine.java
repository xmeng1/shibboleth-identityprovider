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
    private static final Logger log = Logger.getLogger(AuthenticationEngine.class);

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
     * @param loginContext user login context
     */
    public static void returnToAuthenticationEngine(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        HttpSession httpSession = httpRequest.getSession();

        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        
        try {
            RequestDispatcher distpather = httpRequest.getRequestDispatcher(loginContext.getAuthenticationManagerURL());
            distpather.forward(httpRequest, httpResponse);
        } catch (IOException e) {
            log.fatal("Unable to return control back to authentication engine", e);
        } catch (ServletException e) {
            log.fatal("Unable to return control back to authentication engine", e);
        }
    }

    /** {@inheritDoc} */
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        HttpSession httpSession = httpRequest.getSession();

        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (loginContext == null) {
            // TODO error
        }

        // If authentication has been attempted, don't try it again.
        if (loginContext.getAuthenticationAttempted()) {
            handleNewAuthnRequest(loginContext, httpRequest, httpResponse);
        } else {
            finishAuthnRequest(loginContext, httpRequest, httpResponse);
        }
    }

    /**
     * Handle a new authentication request.
     * 
     * @param loginContext The {@link LoginContext} for the new authentication request
     * @param httpRequest The servlet request containing the authn request
     * @param httpResponse The associated servlet response.
     * 
     * @throws IOException thrown if there is a problem reading/writting to the HTTP request/response
     * @throws ServletException thrown if there is a problem transferring control to the authentication handler
     */
    protected void handleNewAuthnRequest(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) throws ServletException, IOException {

        HttpSession httpSession = httpRequest.getSession();
        String shibSessionId = (String) httpSession.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        Session shibSession = getSessionManager().getSession(shibSessionId);

        AuthenticationMethodInformation authenticationMethod = getUsableExistingAuthenticationMethod(loginContext,
                shibSession);
        if (authenticationMethod != null) {
            loginContext.setAuthenticationDuration(authenticationMethod.getAuthenticationDuration());
            loginContext.setAuthenticationInstant(authenticationMethod.getAuthenticationInstant());
            loginContext.setAuthenticationMethod(authenticationMethod.getAuthenticationMethod());
            loginContext.setPrincipalAuthenticated(true);
            loginContext.setPrincipalName(shibSession.getPrincipalName());
            finishAuthnRequest(loginContext, httpRequest, httpResponse);
        } else {
            Pair<String, AuthenticationHandler> handler = getAuthenticationHandlerManager().getAuthenticationHandler(
                    loginContext);

            if (handler == null) {
                loginContext.setPassiveAuth(false);
                loginContext
                        .setAuthenticationFailureMessage("No installed AuthenticationHandler can satisfy the authentication request.");
                log.error("No installed AuthenticationHandler can satisfy the authentication request.");
                finishAuthnRequest(loginContext, httpRequest, httpResponse);
            }

            loginContext.setAuthenticationAttempted();
            loginContext.setAuthenticationDuration(handler.getSecond().getAuthenticationDuration());
            loginContext.setAuthenticationMethod(handler.getFirst());
            loginContext.setAuthenticationManagerURL(httpRequest.getRequestURI());

            httpSession.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);
            handler.getSecond().login(loginContext, httpRequest, httpResponse);
        }
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

    /**
     * Handle the "return leg" of an authentication request (i.e. clean up after an authentication handler has run).
     * 
     * @param loginContext The {@link LoginContext} for the new authentication request
     * @param httpRequest The servlet request containing the authn request
     * @param httpResponse The associated servlet response.
     * 
     * @throws IOException thrown if there is a problem reading/writting to the HTTP request/response
     * @throws ServletException thrown if there is a problem transferring control to the authentication profile handler
     */
    protected void finishAuthnRequest(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) throws ServletException, IOException {

        HttpSession httpSession = httpRequest.getSession();
        String shibSessionId = (String) httpSession.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        Session shibSession = null;
        AuthenticationMethodInformation authnMethodInfo = null;
        ServiceInformation serviceInfo = null;

        if (!loginContext.getAuthenticationAttempted()) {
            // Authentication wasn't attempted so we're using a previously established authentication method
            shibSession = getSessionManager().getSession(shibSessionId);
            authnMethodInfo = shibSession.getAuthenticationMethods().get(loginContext.getAuthenticationMethod());
        } else {
            if (shibSessionId == null) {
                InetAddress addr;
                try {
                    addr = InetAddress.getByName(httpRequest.getRemoteAddr());
                } catch (UnknownHostException ex) {
                    addr = null;
                }

                shibSession = (Session) getSessionManager().createSession(addr, loginContext.getPrincipalName());
                httpSession.setAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE, shibSession.getSessionID());

                authnMethodInfo = new AuthenticationMethodInformationImpl(loginContext.getAuthenticationMethod(),
                        new DateTime(), loginContext.getAuthenticationDuration());
                shibSession.getAuthenticationMethods().put(authnMethodInfo.getAuthenticationMethod(), authnMethodInfo);
            }
        }

        loginContext.setSessionID(shibSession.getSessionID());
        shibSession.setLastActivityInstant(new DateTime());

        serviceInfo = shibSession.getServicesInformation().get(loginContext.getRelyingPartyId());
        if (serviceInfo == null) {
            serviceInfo = new ServiceInformationImpl(loginContext.getRelyingPartyId(), new DateTime(), authnMethodInfo);
        }

        RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(loginContext.getProfileHandlerURL());
        dispatcher.forward(httpRequest, httpResponse);
    }

    // TODO logout support
}