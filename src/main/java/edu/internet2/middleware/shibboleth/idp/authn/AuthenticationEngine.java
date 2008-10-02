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
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.util.storage.ExpiringObject;
import org.opensaml.util.storage.StorageService;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
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

/** Manager responsible for handling authentication requests. */
public class AuthenticationEngine extends HttpServlet {

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

    /** Storage service used to store {@link LoginContext}s while authentication is in progress. */
    private static StorageService<String, LoginContextEntry> storageService;

    /** Name of the storage service partition used to store login contexts. */
    private static String loginContextPartitionName;

    /** Lifetime of stored login contexts. */
    private static long loginContextEntryLifetime;

    /** ID generator. */
    private static IdentifierGenerator idGen;

    /** Profile handler manager. */
    private IdPProfileHandlerManager handlerManager;

    /** Session manager. */
    private SessionManager<Session> sessionManager;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        String handlerManagerId = config.getInitParameter("handlerManagerId");
        if (DatatypeHelper.isEmpty(handlerManagerId)) {
            handlerManagerId = "shibboleth.HandlerManager";
        }
        handlerManager = (IdPProfileHandlerManager) getServletContext().getAttribute(handlerManagerId);

        String sessionManagerId = config.getInitParameter("sessionManagedId");
        if (DatatypeHelper.isEmpty(sessionManagerId)) {
            sessionManagerId = "shibboleth.SessionManager";
        }
        sessionManager = (SessionManager<Session>) getServletContext().getAttribute(sessionManagerId);

        String storageServiceId = config.getInitParameter("storageServiceId");
        if (DatatypeHelper.isEmpty(storageServiceId)) {
            storageServiceId = "shibboleth.StorageService";
        }
        storageService = (StorageService<String, LoginContextEntry>) getServletContext().getAttribute(storageServiceId);

        String partitionName = DatatypeHelper.safeTrimOrNullString(config
                .getInitParameter(LOGIN_CONTEXT_PARTITION_NAME_INIT_PARAM_NAME));
        if (partitionName != null) {
            loginContextPartitionName = partitionName;
        } else {
            loginContextPartitionName = "loginContexts";
        }

        String lifetime = DatatypeHelper.safeTrimOrNullString(config
                .getInitParameter(LOGIN_CONTEXT_LIFETIME_INIT_PARAM_NAME));
        if (lifetime != null) {
            loginContextEntryLifetime = Long.parseLong(lifetime);
        } else {
            loginContextEntryLifetime = 1000 * 60 * 30;
        }

        try {
            idGen = new SecureRandomIdentifierGenerator();
        } catch (NoSuchAlgorithmException e) {
            throw new ServletException("Error create random number generator", e);
        }
    }

    /**
     * Retrieves a login context.
     * 
     * @param httpRequest current HTTP request
     * @param removeFromStorageService whether the login context should be removed from the storage service as it is
     *            retrieved
     * 
     * @return the login context or null if one is not available (e.g. because it has expired)
     */
    protected static LoginContext retrieveLoginContext(HttpServletRequest httpRequest, boolean removeFromStorageService) {
        // When the login context comes from the profile handlers its attached to the request
        // Prior to the authentication engine handing control over to a login handler it stores
        // the login context into the storage service so that the login handlers do not have to
        // maintain a reference to the context and return it to the engine.
        LoginContext loginContext = (LoginContext) httpRequest.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (loginContext != null) {
            LOG.trace("Login context retrieved from HTTP request attribute");
            return loginContext;
        }

        String contextId = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                .getAttribute(LOGIN_CONTEXT_KEY_NAME));

        if (contextId == null) {
            Cookie[] requestCookies = httpRequest.getCookies();
            if (requestCookies != null) {
                for (Cookie requestCookie : requestCookies) {
                    if (DatatypeHelper.safeEquals(requestCookie.getName(), LOGIN_CONTEXT_KEY_NAME)) {
                        LOG.trace("Located cookie with login context key");
                        contextId = requestCookie.getValue();
                        break;
                    }
                }
            }
        }

        LOG.trace("Using login context key {} to look up login context", contextId);
        LoginContextEntry entry;
        if (removeFromStorageService) {
            entry = storageService.remove(loginContextPartitionName, contextId);
        } else {
            entry = storageService.get(loginContextPartitionName, contextId);
        }
        if (entry == null) {
            LOG.trace("No entry for login context found in storage service.");
            return null;
        } else if (entry.isExpired()) {
            LOG.trace("Login context entry found in storage service but it was expired.");
            return null;
        } else {
            LOG.trace("Login context entry found in storage service.");
            return entry.getLoginContext();
        }
    }

    /**
     * Returns control back to the authentication engine.
     * 
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    public static void returnToAuthenticationEngine(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        LOG.debug("Returning control to authentication engine");
        LoginContext loginContext = retrieveLoginContext(httpRequest, false);
        if (loginContext == null) {
            LOG.error("No login context available, unable to return to authentication engine");
            forwardRequest("/idp-error.jsp", httpRequest, httpResponse);
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
    public static void returnToProfileHandler(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        LOG.debug("Returning control to profile handler at: {}", loginContext.getProfileHandlerURL());
        httpRequest.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);
        
        // Cleanup this cookie
        Cookie lcKeyCookie = new Cookie(LOGIN_CONTEXT_KEY_NAME, "");
        lcKeyCookie.setMaxAge(0);
        httpResponse.addCookie(lcKeyCookie);
        
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

        LoginContext loginContext = retrieveLoginContext(httpRequest, true);
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
        LOG.debug("Beginning user authentication process");
        try {
            Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
            if (idpSession != null) {
                LOG.debug("Existing IdP session available for principal {}", idpSession.getPrincipalName());
            }

            Map<String, LoginHandler> possibleLoginHandlers = determinePossibleLoginHandlers(loginContext);
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
                Entry<String, LoginHandler> chosenLoginHandler = possibleLoginHandlers.entrySet().iterator().next();
                loginContext.setAttemptedAuthnMethod(chosenLoginHandler.getKey());
                loginHandler = chosenLoginHandler.getValue();
            }

            // Send the request to the login handler
            LOG.debug("Authenticating user with login handler of type {}", loginHandler.getClass().getName());
            loginContext.setAuthenticationAttempted();
            loginContext.setAuthenticationEngineURL(HttpHelper.getRequestUriWithoutContext(httpRequest));
            storeLoginContext(loginContext, httpRequest, httpResponse);
            loginHandler.login(httpRequest, httpResponse);
        } catch (AuthenticationException e) {
            loginContext.setAuthenticationFailure(e);
            returnToProfileHandler(loginContext, httpRequest, httpResponse);
        }
    }

    /**
     * Determines which configured login handlers will support the requested authentication methods.
     * 
     * @param loginContext current login context
     * 
     * @return login methods that may be used to authenticate the user
     * 
     * @throws AuthenticationException thrown if no login handler meets the given requirements
     */
    protected Map<String, LoginHandler> determinePossibleLoginHandlers(LoginContext loginContext)
            throws AuthenticationException {
        Map<String, LoginHandler> supportedLoginHandlers = new HashMap<String, LoginHandler>(handlerManager
                .getLoginHandlers());
        LOG.trace("Supported login handlers: {}", supportedLoginHandlers);
        LOG.trace("Requested authentication methods: {}", loginContext.getRequestedAuthenticationMethods());

        // If no preferences Authn method preference is given, then we're free to use any
        if (loginContext.getRequestedAuthenticationMethods().isEmpty()) {
            LOG.trace("No preference given for authentication methods");
            return supportedLoginHandlers;
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
            LOG.error("No authentication method, requested by the service provider, is supported");
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
            LOG.error("Passive authentication required but no login handlers available to support it");
            throw new PassiveAuthenticationException();
        }
    }

    /**
     * Stores the login context in the storage service. The key for the stored login context is then bound to an HTTP
     * request attribute and set a cookie.
     * 
     * @param loginContext login context to store
     * @param httpRequest current HTTP request
     * @param httpResponse current HTTP response
     */
    protected void storeLoginContext(LoginContext loginContext, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        String contextId = idGen.generateIdentifier();

        storageService.put(loginContextPartitionName, contextId, new LoginContextEntry(loginContext,
                loginContextEntryLifetime));

        httpRequest.setAttribute(LOGIN_CONTEXT_KEY_NAME, contextId);

        Cookie cookie = new Cookie(LOGIN_CONTEXT_KEY_NAME, contextId);
        String contextPath = httpRequest.getContextPath();
        if (DatatypeHelper.isEmpty(contextPath)) {
            cookie.setPath("/");
        } else {
            cookie.setPath(contextPath);
        }
        cookie.setSecure(httpRequest.isSecure());
        cookie.setMaxAge(-1);
        httpResponse.addCookie(cookie);
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
            // Check to make sure the login handler did the right thing
            validateSuccessfulAuthentication(loginContext, httpRequest);

            // We allow a login handler to override the authentication method in the
            // event that it supports multiple methods
            String actualAuthnMethod = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                    .getAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY));
            if (actualAuthnMethod == null) {
                actualAuthnMethod = loginContext.getAttemptedAuthnMethod();
            }

            // Get the Subject from the request. If force authentication was required then make sure the
            // Subject identifies the same user that authenticated before
            Subject subject = getLoginHandlerSubject(httpRequest);
            if (loginContext.isForceAuthRequired()) {
                validateForcedReauthentication(idpSession, actualAuthnMethod, subject);
            }

            loginContext.setPrincipalAuthenticated(true);
            updateUserSession(loginContext, subject, actualAuthnMethod, httpRequest, httpResponse);
            LOG.debug("User {} authenticated with method {}", loginContext.getPrincipalName(), actualAuthnMethod);
        } catch (AuthenticationException e) {
            LOG.error("Authentication failed with the error:", e);
            loginContext.setPrincipalAuthenticated(false);
            loginContext.setAuthenticationFailure(e);
        }

        returnToProfileHandler(loginContext, httpRequest, httpResponse);
    }

    /**
     * Validates that the authentication was successfully performed by the login handler. An authentication is
     * considered successful if no error is bound to the request attribute {@link LoginHandler#AUTHENTICATION_ERROR_KEY}
     * and there is a value for at least one of the following request attributes: {@link LoginHandler#SUBJECT_KEY},
     * {@link LoginHandler#PRINCIPAL_KEY}, or {@link LoginHandler#PRINCIPAL_NAME_KEY}.
     * 
     * @param loginContext current login context
     * @param httpRequest current HTTP request
     * 
     * @throws AuthenticationException thrown if the authentication was not successful
     */
    protected void validateSuccessfulAuthentication(LoginContext loginContext, HttpServletRequest httpRequest)
            throws AuthenticationException {
        String errorMessage = DatatypeHelper.safeTrimOrNullString((String) httpRequest
                .getAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY));
        if (errorMessage != null) {
            LOG.error("Error returned from login handler for authentication method {}:\n{}", loginContext
                    .getAttemptedAuthnMethod(), errorMessage);
            throw new AuthenticationException(errorMessage);
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
        LoginHandler loginHandler = handlerManager.getLoginHandlers().get(authenticationMethod);
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
     * Merges the principals and public and private credentials from two subjects into a new subject.
     * 
     * @param subject1 first subject to merge, may be null
     * @param subject2 second subject to merge, may be null
     * 
     * @return subject containing the merged information
     */
    protected Subject mergeSubjects(Subject subject1, Subject subject2) {
        if (subject1 == null) {
            return subject2;
        }

        if (subject2 == null) {
            return subject1;
        }

        if (subject1 == null && subject2 == null) {
            return new Subject();
        }

        Set<Principal> principals = new HashSet<Principal>();
        principals.addAll(subject1.getPrincipals());
        principals.addAll(subject2.getPrincipals());

        Set<Object> publicCredentials = new HashSet<Object>();
        publicCredentials.addAll(subject1.getPublicCredentials());
        publicCredentials.addAll(subject2.getPublicCredentials());

        Set<Object> privateCredentials = new HashSet<Object>();
        privateCredentials.addAll(subject1.getPrivateCredentials());
        privateCredentials.addAll(subject2.getPrivateCredentials());

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

        String remoteAddress = httpRequest.getRemoteAddr();
        String sessionId = userSession.getSessionID();
        
        String signature = null;
        SecretKey signingKey = userSession.getSessionSecretKey();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);
            mac.update(remoteAddress.getBytes());
            mac.update(sessionId.getBytes());
            signature = Base64.encodeBytes(mac.doFinal());
        } catch (GeneralSecurityException e) {
            LOG.error("Unable to compute signature over session cookie material", e);
        }

        LOG.debug("Adding IdP session cookie to HTTP response");
        Cookie sessionCookie = new Cookie(IDP_SESSION_COOKIE_NAME, remoteAddress + "|" + sessionId + "|" + signature);

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

    /** Storage service entry for login contexts. */
    public class LoginContextEntry implements ExpiringObject {

        /** Stored login context. */
        private LoginContext loginCtx;

        /** Time the entry expires. */
        private DateTime expirationTime;

        /**
         * Constructor.
         * 
         * @param ctx context to store
         * @param lifetime lifetime of the entry
         */
        public LoginContextEntry(LoginContext ctx, long lifetime) {
            loginCtx = ctx;
            expirationTime = new DateTime().plus(lifetime);
        }

        /**
         * Gets the login context.
         * 
         * @return login context
         */
        public LoginContext getLoginContext() {
            return loginCtx;
        }

        /** {@inheritDoc} */
        public DateTime getExpirationTime() {
            return expirationTime;
        }

        /** {@inheritDoc} */
        public boolean isExpired() {
            return expirationTime.isBeforeNow();
        }

        /** {@inheritDoc} */
        public void onExpire() {

        }
    }
}