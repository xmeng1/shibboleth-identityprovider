/*
 * Copyright 2006 University Corporation for Advanced Internet Development, Inc.
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
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.util.storage.StorageService;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.MessageFormatter;

import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.common.util.HttpHelper;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;
import edu.internet2.middleware.shibboleth.idp.session.impl.ServiceInformationImpl;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/** Manager responsible for handling authentication requests. */
public class AuthenticationEngine extends HttpServlet {

    /**
     * Name of the Servlet config init parameter that indicates whether the public credentials of a {@link Subject} are
     * retained after authentication.
     */
    public static final String RETAIN_PUBLIC_CREDENTIALS = "retainSubjectsPublicCredentials";

    /**
     * Name of the Servlet config init parameter that indicates whether the private credentials of a {@link Subject} are
     * retained after authentication.
     */
    public static final String RETAIN_PRIVATE_CREDENTIALS = "retainSubjectsPrivateCredentials";

    /** Name of the Servlet config init parameter that holds the partition name for login contexts. */
    public static final String LOGIN_CONTEXT_PARTITION_NAME_INIT_PARAM_NAME = "loginContextPartitionName";

    /** Name of the Servlet config init parameter that holds lifetime of a login context in the storage service. */
    public static final String LOGIN_CONTEXT_LIFETIME_INIT_PARAM_NAME = "loginContextEntryLifetime";

    /** Name of the IdP Cookie containing the IdP session ID. */
    public static final String IDP_SESSION_COOKIE_NAME = "_idp_session";

    /** Name of the key under which to bind the storage service key for a login context. */
    public static final String LOGIN_CONTEXT_KEY_NAME = "_idp_authn_lc_key";

    /** Serial version UID. */
    private static final long serialVersionUID = -8479060989001890156L;

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationEngine.class);

    // TODO remove once HttpServletHelper does redirects
    private static ServletContext context;

    /** Storage service used to store {@link LoginContext}s while authentication is in progress. */
    private static StorageService<String, LoginContextEntry> storageService;

    /** Whether the public credentials of a {@link Subject} are retained after authentication. */
    private boolean retainSubjectsPublicCredentials;

    /** Whether the private credentials of a {@link Subject} are retained after authentication. */
    private boolean retainSubjectsPrivateCredentials;

    /** Profile handler manager. */
    private IdPProfileHandlerManager handlerManager;

    /** Session manager. */
    private SessionManager<Session> sessionManager;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        String retain = DatatypeHelper.safeTrimOrNullString(config.getInitParameter(RETAIN_PRIVATE_CREDENTIALS));
        if (retain != null) {
            retainSubjectsPrivateCredentials = Boolean.parseBoolean(retain);
        } else {
            retainSubjectsPrivateCredentials = false;
        }

        retain = DatatypeHelper.safeTrimOrNullString(config.getInitParameter(RETAIN_PUBLIC_CREDENTIALS));
        if (retain != null) {
            retainSubjectsPublicCredentials = Boolean.parseBoolean(retain);
        } else {
            retainSubjectsPublicCredentials = false;
        }

        handlerManager = HttpServletHelper.getProfileHandlerManager(config.getServletContext());
        sessionManager = HttpServletHelper.getSessionManager(config.getServletContext());
        storageService = (StorageService<String, LoginContextEntry>) HttpServletHelper.getStorageService(config
                .getServletContext());

        context = config.getServletContext();
    }

    /**
     * Returns control back to the authentication engine.
     * 
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    public static void returnToAuthenticationEngine(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        LOG.debug("Returning control to authentication engine");
        LoginContext loginContext = HttpServletHelper.getLoginContext(storageService, context, httpRequest);
        if (loginContext == null) {
            LOG.warn("No login context available, unable to return to authentication engine");
            forwardRequest("/error.jsp", httpRequest, httpResponse);
        } else {
            forwardRequest(loginContext.getAuthenticationEngineURL(), httpRequest, httpResponse);
        }
    }

    /**
     * Returns control back to the profile handler that invoked the authentication engine.
     * 
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    public static void returnToProfileHandler(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        LOG.debug("Returning control to profile handler");
        LoginContext loginContext = HttpServletHelper.getLoginContext(storageService, context, httpRequest);
        if (loginContext == null) {
            LOG.warn("No login context available, unable to return to profile handler");
            forwardRequest("/error.jsp", httpRequest, httpResponse);
        }

        HttpServletHelper.bindLoginContext(loginContext, httpRequest);
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

        LoginContext loginContext = HttpServletHelper.getLoginContext(storageService, getServletContext(), httpRequest);
        if (loginContext == null) {
            LOG.error("Incoming request does not have attached login context");
            throw new ServletException("Incoming request does not have attached login context");
        }

        if (!loginContext.getAuthenticationAttempted()) {
            startUserAuthentication(loginContext, httpRequest, httpResponse);
        } else {
            completeAuthentication(loginContext, httpRequest, httpResponse);
        }
    }

    /**
     * Begins the authentication process. Determines if forced re-authentication is required or if an existing, active,
     * authentication method is sufficient. Also determines, when authentication is required, which handler to use
     * depending on whether passive authentication is required.
     * 
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void startUserAuthentication(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        LOG.debug("Beginning user authentication process.");
        try {
            Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
            if (idpSession != null) {
                LOG.debug("Existing IdP session available for principal {}", idpSession.getPrincipalName());
            }

            Map<String, LoginHandler> possibleLoginHandlers = determinePossibleLoginHandlers(idpSession, loginContext);
            LOG.debug("Possible authentication handlers for this request: {}", possibleLoginHandlers);

            // Filter out possible candidate login handlers by forced and passive authentication requirements
            if (loginContext.isForceAuthRequired()) {
                filterByForceAuthentication(idpSession, loginContext, possibleLoginHandlers);
            }

            if (loginContext.isPassiveAuthRequired()) {
                filterByPassiveAuthentication(idpSession, loginContext, possibleLoginHandlers);
            }

            // If the user already has a session and its usage is acceptable than use it
            // otherwise just use the first candidate login handler
            LOG.debug("Possible authentication handlers after filtering: {}", possibleLoginHandlers);
            LoginHandler loginHandler;
            if (idpSession != null && possibleLoginHandlers.containsKey(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX)) {
                loginContext.setAttemptedAuthnMethod(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
                loginHandler = possibleLoginHandlers.get(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
            } else {
                possibleLoginHandlers.remove(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
                if (possibleLoginHandlers.isEmpty()) {
                    LOG.info("No authentication mechanism available for use with relying party '{}'", loginContext
                            .getRelyingPartyId());
                    throw new AuthenticationException();
                }

                if (loginContext.getDefaultAuthenticationMethod() != null
                        && possibleLoginHandlers.containsKey(loginContext.getDefaultAuthenticationMethod())) {
                    loginHandler = possibleLoginHandlers.get(loginContext.getDefaultAuthenticationMethod());
                    loginContext.setAttemptedAuthnMethod(loginContext.getDefaultAuthenticationMethod());
                } else {
                    Entry<String, LoginHandler> chosenLoginHandler = possibleLoginHandlers.entrySet().iterator().next();
                    loginContext.setAttemptedAuthnMethod(chosenLoginHandler.getKey());
                    loginHandler = chosenLoginHandler.getValue();
                }
            }

            LOG.debug("Authenticating user with login handler of type {}", loginHandler.getClass().getName());
            loginContext.setAuthenticationAttempted();
            loginContext.setAuthenticationEngineURL(HttpHelper.getRequestUriWithoutContext(httpRequest));

            // Send the request to the login handler
            HttpServletHelper.bindLoginContext(loginContext, storageService, getServletContext(), httpRequest,
                    httpResponse);
            loginHandler.login(httpRequest, httpResponse);
        } catch (AuthenticationException e) {
            loginContext.setAuthenticationFailure(e);
            returnToProfileHandler(httpRequest, httpResponse);
        }
    }

    /**
     * Determines which configured login handlers will support the requested authentication methods.
     * 
     * @param loginContext current login context
     * @param idpSession current user's session, or null if they don't have one
     * 
     * @return login methods that may be used to authenticate the user
     * 
     * @throws AuthenticationException thrown if no login handler meets the given requirements
     */
    protected Map<String, LoginHandler> determinePossibleLoginHandlers(Session idpSession, LoginContext loginContext)
            throws AuthenticationException {
        Map<String, LoginHandler> supportedLoginHandlers = new HashMap<String, LoginHandler>(handlerManager
                .getLoginHandlers());
        LOG.debug("Filtering configured login handlers by requested athentication methods.");
        LOG.debug("Configured LoginHandlers: {}", supportedLoginHandlers);
        LOG.debug("Requested authentication methods: {}", loginContext.getRequestedAuthenticationMethods());

        // If no preferences Authn method preference is given, then we're free to use any
        if (loginContext.getRequestedAuthenticationMethods().isEmpty()) {
            LOG.trace("No preference given for authentication methods");
            return supportedLoginHandlers;
        }

        // If the previous session handler is configured, the user has an existing session, and the SP requested
        // that a certain set of authentication methods be used then we need to check to see if the user has
        // authenticated with one or more of those methods, if not we can't use the previous session handler
        if (supportedLoginHandlers.containsKey(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX) && idpSession != null
                && loginContext.getRequestedAuthenticationMethods() != null) {
            boolean retainPreviousSession = false;

            Map<String, AuthenticationMethodInformation> currentAuthnMethods = idpSession.getAuthenticationMethods();
            for (String currentAuthnMethod : currentAuthnMethods.keySet()) {
                if (loginContext.getRequestedAuthenticationMethods().contains(currentAuthnMethod)) {
                    retainPreviousSession = true;
                    break;
                }
            }

            if (!retainPreviousSession) {
                supportedLoginHandlers.remove(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
            }
        }

        // Otherwise we need to filter all the mechanism supported by the IdP so that only the request types are left
        // Previous session handler is a special case, we always to keep that around if it's configured
        Iterator<Entry<String, LoginHandler>> supportedLoginHandlerItr = supportedLoginHandlers.entrySet().iterator();
        Entry<String, LoginHandler> supportedLoginHandler;
        while (supportedLoginHandlerItr.hasNext()) {
            supportedLoginHandler = supportedLoginHandlerItr.next();
            if (!supportedLoginHandler.getKey().equals(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX)
                    && !loginContext.getRequestedAuthenticationMethods().contains(supportedLoginHandler.getKey())) {
                supportedLoginHandlerItr.remove();
                continue;
            }
        }

        if (supportedLoginHandlers.isEmpty()) {
            LOG.warn("No authentication method, requested by the service provider, is supported");
            throw new AuthenticationException(
                    "No authentication method, requested by the service provider, is supported");
        }

        return supportedLoginHandlers;
    }

    /**
     * Filters out any login handler based on the requirement for forced authentication.
     * 
     * During forced authentication any handler that has not previously been used to authenticate the user or any
     * handlers that have been and support force re-authentication may be used. Filter out any of the other ones.
     * 
     * @param idpSession user's current IdP session
     * @param loginContext current login context
     * @param loginHandlers login handlers to filter
     * 
     * @throws ForceAuthenticationException thrown if no handlers remain after filtering
     */
    protected void filterByForceAuthentication(Session idpSession, LoginContext loginContext,
            Map<String, LoginHandler> loginHandlers) throws ForceAuthenticationException {
        LOG.debug("Forced authentication is required, filtering possible login handlers accordingly");

        ArrayList<AuthenticationMethodInformation> activeMethods = new ArrayList<AuthenticationMethodInformation>();
        if (idpSession != null) {
            activeMethods.addAll(idpSession.getAuthenticationMethods().values());
        }

        loginHandlers.remove(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);

        LoginHandler loginHandler;
        for (AuthenticationMethodInformation activeMethod : activeMethods) {
            loginHandler = loginHandlers.get(activeMethod.getAuthenticationMethod());
            if (loginHandler != null && !loginHandler.supportsForceAuthentication()) {
                for (String handlerSupportedMethods : loginHandler.getSupportedAuthenticationMethods()) {
                    loginHandlers.remove(handlerSupportedMethods);
                }
            }
        }

        LOG.debug("Authentication handlers remaining after forced authentication requirement filtering: {}",
                loginHandlers);

        if (loginHandlers.isEmpty()) {
            LOG.info("Force authentication requested but no login handlers available to support it");
            throw new ForceAuthenticationException();
        }
    }

    /**
     * Filters out any login handler that doesn't support passive authentication if the login context indicates passive
     * authentication is required.
     * 
     * @param idpSession user's current IdP session
     * @param loginContext current login context
     * @param loginHandlers login handlers to filter
     * 
     * @throws PassiveAuthenticationException thrown if no handlers remain after filtering
     */
    protected void filterByPassiveAuthentication(Session idpSession, LoginContext loginContext,
            Map<String, LoginHandler> loginHandlers) throws PassiveAuthenticationException {
        LOG.debug("Passive authentication is required, filtering poassible login handlers accordingly.");

        if (idpSession == null) {
            loginHandlers.remove(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX);
        }

        LoginHandler loginHandler;
        Iterator<Entry<String, LoginHandler>> authnMethodItr = loginHandlers.entrySet().iterator();
        while (authnMethodItr.hasNext()) {
            loginHandler = authnMethodItr.next().getValue();
            if (!loginHandler.supportsPassive()) {
                authnMethodItr.remove();
            }
        }

        LOG.debug("Authentication handlers remaining after passive authentication requirement filtering: {}",
                loginHandlers);

        if (loginHandlers.isEmpty()) {
            LOG.warn("Passive authentication required but no login handlers available to support it");
            throw new PassiveAuthenticationException();
        }
    }

    /**
     * Completes the authentication process.
     * 
     * The principal name set by the authentication handler is retrieved and pushed in to the login context, a
     * Shibboleth session is created if needed, information indicating that the user has logged into the service is
     * recorded and finally control is returned back to the profile handler.
     * 
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void completeAuthentication(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        LOG.debug("Completing user authentication process");

        Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);

        try {
            // We allow a login handler to override the authentication method in the
            // event that it supports multiple methods
            String actualAuthnMethod = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                    .getAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY));
            if (actualAuthnMethod != null) {
                if (!loginContext.getRequestedAuthenticationMethods().isEmpty()
                        && !loginContext.getRequestedAuthenticationMethods().contains(actualAuthnMethod)) {
                    String msg = MessageFormatter.format(
                                    "Relying patry required an authentication method of '{}' but the login handler performed '{}'",
                                    loginContext.getRequestedAuthenticationMethods(), actualAuthnMethod);
                    LOG.error(msg);
                    throw new AuthenticationException(msg);
                }
            } else {
                actualAuthnMethod = loginContext.getAttemptedAuthnMethod();
            }

            // Check to make sure the login handler did the right thing
            validateSuccessfulAuthentication(loginContext, httpRequest, actualAuthnMethod);

            // Get the Subject from the request. If force authentication was required then make sure the
            // Subject identifies the same user that authenticated before
            Subject subject = getLoginHandlerSubject(httpRequest);
            if (loginContext.isForceAuthRequired()) {
                validateForcedReauthentication(idpSession, actualAuthnMethod, subject);
            }

            loginContext.setPrincipalAuthenticated(true);
            updateUserSession(loginContext, subject, actualAuthnMethod, httpRequest, httpResponse);
            LOG.debug("User {} authenticated with method {}", loginContext.getPrincipalName(), loginContext
                    .getAuthenticationMethod());
        } catch (AuthenticationException e) {
            LOG.error("Authentication failed with the error:", e);
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailure(e);
        }

        returnToProfileHandler(httpRequest, httpResponse);
    }

    /**
     * Validates that the authentication was successfully performed by the login handler. An authentication is
     * considered successful if no error is bound to the request attribute {@link LoginHandler#AUTHENTICATION_ERROR_KEY}
     * and there is a value for at least one of the following request attributes: {@link LoginHandler#SUBJECT_KEY},
     * {@link LoginHandler#PRINCIPAL_KEY}, or {@link LoginHandler#PRINCIPAL_NAME_KEY}.
     * 
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * @param authenticationMethod the authentication method used to authenticate the user
     * 
     * @throws AuthenticationException thrown if the authentication was not successful
     */
    protected void validateSuccessfulAuthentication(LoginContext loginContext, HttpServletRequest httpRequest,
            String authenticationMethod) throws AuthenticationException {
        LOG.debug("Validating authentication was performed successfully");

        String errorMessage = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                .getAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY));
        if (errorMessage != null) {
            LOG.error("Error returned from login handler for authentication method {}:\n{}", loginContext
                    .getAttemptedAuthnMethod(), errorMessage);
            throw new AuthenticationException(errorMessage);
        }

        AuthenticationException authnException = (AuthenticationException) httpRequest
                .getAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY);
        if (authnException != null) {
            throw authnException;
        }

        Subject subject = (Subject) httpRequest.getAttribute(LoginHandler.SUBJECT_KEY);
        Principal principal = (Principal) httpRequest.getAttribute(LoginHandler.PRINCIPAL_KEY);
        String principalName = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                .getAttribute(LoginHandler.PRINCIPAL_NAME_KEY));

        if (subject == null && principal == null && principalName == null) {
            LOG.error("No user identified by login handler.");
            throw new AuthenticationException("No user identified by login handler.");
        }
    }

    /**
     * Gets the subject from the request coming back from the login handler.
     * 
     * @param httpRequest request coming back from the login handler
     * 
     * @return the {@link Subject} created from the request
     * 
     * @throws AuthenticationException thrown if no subject can be retrieved from the request
     */
    protected Subject getLoginHandlerSubject(HttpServletRequest httpRequest) throws AuthenticationException {
        Subject subject = (Subject) httpRequest.getAttribute(LoginHandler.SUBJECT_KEY);
        Principal principal = (Principal) httpRequest.getAttribute(LoginHandler.PRINCIPAL_KEY);
        String principalName = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                .getAttribute(LoginHandler.PRINCIPAL_NAME_KEY));

        if (subject == null && (principal != null || principalName != null)) {
            subject = new Subject();
            if (principal == null) {
                principal = new UsernamePrincipal(principalName);
            }
            subject.getPrincipals().add(principal);
        }

        return subject;
    }

    /**
     * If forced authentication was required this method checks to ensure that the re-authenticated subject contains a
     * principal name that is equal to the principal name associated with the authentication method. If this is the
     * first time the subject has authenticated with this method than this check always passes.
     * 
     * @param idpSession user's IdP session
     * @param authnMethod method used to authenticate the user
     * @param subject subject that was authenticated
     * 
     * @throws AuthenticationException thrown if this check fails
     */
    protected void validateForcedReauthentication(Session idpSession, String authnMethod, Subject subject)
            throws AuthenticationException {
        if (idpSession != null) {
            AuthenticationMethodInformation authnMethodInfo = idpSession.getAuthenticationMethods().get(authnMethod);
            if (authnMethodInfo != null) {
                boolean princpalMatch = false;
                for (Principal princpal : subject.getPrincipals()) {
                    if (authnMethodInfo.getAuthenticationPrincipal().equals(princpal)) {
                        princpalMatch = true;
                        break;
                    }
                }

                if (!princpalMatch) {
                    throw new ForceAuthenticationException(
                            "Authenticated principal does not match previously authenticated principal");
                }
            }
        }
    }

    /**
     * Updates the user's Shibboleth session with authentication information. If no session exists a new one will be
     * created.
     * 
     * @param loginContext current login context
     * @param authenticationSubject subject created from the authentication method
     * @param authenticationMethod the method used to authenticate the subject
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void updateUserSession(LoginContext loginContext, Subject authenticationSubject,
            String authenticationMethod, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        Principal authenticationPrincipal = authenticationSubject.getPrincipals().iterator().next();
        LOG.debug("Updating session information for principal {}", authenticationPrincipal.getName());

        Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        if (idpSession == null) {
            LOG.debug("Creating shibboleth session for principal {}", authenticationPrincipal.getName());
            idpSession = (Session) sessionManager.createSession();
            loginContext.setSessionID(idpSession.getSessionID());
            addSessionCookie(httpRequest, httpResponse, idpSession);
        }

        // Merge the information in the current session subject with the information from the
        // login handler subject
        idpSession.setSubject(mergeSubjects(idpSession.getSubject(), authenticationSubject));

        LOG.debug("Recording authentication and service information in Shibboleth session for principal: {}",
                authenticationPrincipal.getName());
        LoginHandler loginHandler = handlerManager.getLoginHandlers().get(loginContext.getAttemptedAuthnMethod());
        AuthenticationMethodInformation authnMethodInfo = new AuthenticationMethodInformationImpl(idpSession
                .getSubject(), authenticationPrincipal, authenticationMethod, new DateTime(), loginHandler
                .getAuthenticationDuration());

        loginContext.setAuthenticationMethodInformation(authnMethodInfo);
        idpSession.getAuthenticationMethods().put(authnMethodInfo.getAuthenticationMethod(), authnMethodInfo);
        sessionManager.indexSession(idpSession, authnMethodInfo.getAuthenticationPrincipal().getName());

        ServiceInformation serviceInfo = new ServiceInformationImpl(loginContext.getRelyingPartyId(), new DateTime(),
                authnMethodInfo);
        idpSession.getServicesInformation().put(serviceInfo.getEntityID(), serviceInfo);
    }

    /**
     * Merges the two {@link Subject}s in to a new {@link Subject}. The new subjects contains all the {@link Principal}s
     * from both subjects. If {@link #retainSubjectsPrivateCredentials} is true then the new subject will contain all
     * the private credentials from both subjects, if not the new subject will not contain private credentials. If
     * {@link #retainSubjectsPublicCredentials} is true then the new subject will contain all the public credentials
     * from both subjects, if not the new subject will not contain public credentials.
     * 
     * @param subject1 first subject to merge, may be null
     * @param subject2 second subject to merge, may be null
     * 
     * @return subject containing the merged information
     */
    protected Subject mergeSubjects(Subject subject1, Subject subject2) {
        if (subject1 == null && subject2 == null) {
            return new Subject();
        }

        if (subject1 == null) {
            return subject2;
        }

        if (subject2 == null) {
            return subject1;
        }

        Set<Principal> principals = new HashSet<Principal>(3);
        principals.addAll(subject1.getPrincipals());
        principals.addAll(subject2.getPrincipals());

        Set<Object> publicCredentials = new HashSet<Object>(3);
        if (retainSubjectsPublicCredentials) {
            LOG.debug("Merging in subjects public credentials");
            publicCredentials.addAll(subject1.getPublicCredentials());
            publicCredentials.addAll(subject2.getPublicCredentials());
        }

        Set<Object> privateCredentials = new HashSet<Object>(3);
        if (retainSubjectsPrivateCredentials) {
            LOG.debug("Merging in subjects private credentials");
            privateCredentials.addAll(subject1.getPrivateCredentials());
            privateCredentials.addAll(subject2.getPrivateCredentials());
        }

        return new Subject(false, principals, publicCredentials, privateCredentials);
    }

    /**
     * Adds an IdP session cookie to the outbound response.
     * 
     * @param httpRequest current request
     * @param httpResponse current response
     * @param userSession user's session
     */
    protected void addSessionCookie(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
            Session userSession) {
        httpRequest.setAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE, userSession);

        byte[] remoteAddress = httpRequest.getRemoteAddr().getBytes();
        byte[] sessionId = userSession.getSessionID().getBytes();

        String signature = null;
        try {
            MessageDigest digester = MessageDigest.getInstance("SHA");
            digester.update(userSession.getSessionSecret());
            digester.update(remoteAddress);
            digester.update(sessionId);
            signature = Base64.encodeBytes(digester.digest());
        } catch (GeneralSecurityException e) {
            LOG.error("Unable to compute signature over session cookie material", e);
        }

        LOG.debug("Adding IdP session cookie to HTTP response");
        StringBuilder cookieValue = new StringBuilder();
        cookieValue.append(Base64.encodeBytes(remoteAddress, Base64.DONT_BREAK_LINES)).append("|");
        cookieValue.append(Base64.encodeBytes(sessionId, Base64.DONT_BREAK_LINES)).append("|");
        cookieValue.append(signature);
        Cookie sessionCookie = new Cookie(IDP_SESSION_COOKIE_NAME, HTTPTransportUtils.urlEncode(cookieValue.toString()));

        String contextPath = httpRequest.getContextPath();
        if (DatatypeHelper.isEmpty(contextPath)) {
            sessionCookie.setPath("/");
        } else {
            sessionCookie.setPath(contextPath);
        }

        sessionCookie.setSecure(httpRequest.isSecure());
        sessionCookie.setMaxAge(-1);

        httpResponse.addCookie(sessionCookie);
    }
}