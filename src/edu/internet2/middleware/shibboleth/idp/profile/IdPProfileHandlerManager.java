/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.profile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.concurrent.locks.Lock;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.opensaml.util.resource.Resource;
import org.opensaml.xml.util.Pair;
import org.springframework.context.ApplicationContext;

import edu.internet2.middleware.shibboleth.common.config.BaseReloadableService;
import edu.internet2.middleware.shibboleth.common.profile.AbstractErrorHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractRequestURIMappedProfileHandler;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;

/**
 * Implementation of a {@link ProfileHandlerManager} that maps the request path, without the servlet context, to a
 * profile handler and adds support for authentication handlers.
 */
public class IdPProfileHandlerManager extends BaseReloadableService implements ProfileHandlerManager {

    /** Class logger. */
    private final Logger log = Logger.getLogger(IdPProfileHandlerManager.class);

    /** Handler used for errors. */
    private AbstractErrorHandler errorHandler;

    /** Map of request paths to profile handlers. */
    private Map<String, AbstractRequestURIMappedProfileHandler> profileHandlers;

    /** Map of authentication methods to authentication handlers. */
    private Map<String, AuthenticationHandler> authenticationHandlers;

    /**
     * Constructor. Configuration resources are not monitored for changes.
     * 
     * @param configurations configuration resources for this service
     */
    public IdPProfileHandlerManager(List<Resource> configurations) {
        super(configurations);
        profileHandlers = new HashMap<String, AbstractRequestURIMappedProfileHandler>();
        authenticationHandlers = new HashMap<String, AuthenticationHandler>();
    }

    /**
     * Constructor.
     * 
     * @param timer timer resource polling tasks are scheduled with
     * @param configurations configuration resources for this service
     * @param pollingFrequency the frequency, in milliseconds, to poll the policy resources for changes, must be greater
     *            than zero
     */
    public IdPProfileHandlerManager(List<Resource> configurations, Timer timer, long pollingFrequency) {
        super(timer, configurations, pollingFrequency);
        profileHandlers = new HashMap<String, AbstractRequestURIMappedProfileHandler>();
        authenticationHandlers = new HashMap<String, AuthenticationHandler>();
    }

    /** {@inheritDoc} */
    public AbstractErrorHandler getErrorHandler() {
        return errorHandler;
    }

    /**
     * Sets the error handler.
     * 
     * @param handler error handler
     */
    public void setErrorHandler(AbstractErrorHandler handler) {
        if (handler == null) {
            throw new IllegalArgumentException("Error handler may not be null");
        }
        errorHandler = handler;
    }

    /** {@inheritDoc} */
    public ProfileHandler getProfileHandler(ServletRequest request) {
        ProfileHandler handler;

        String requestPath = ((HttpServletRequest) request).getPathInfo();
        if (log.isDebugEnabled()) {
            log.debug(getId() + ": Looking up profile handler for request path: " + requestPath);
        }
        Lock readLock = getReadWriteLock().readLock();
        readLock.lock();
        handler = profileHandlers.get(requestPath);
        readLock.unlock();

        if (handler != null) {
            if (log.isDebugEnabled()) {
                log.debug(getId() + ": Located profile handler of the following type for request path "
                        + requestPath + ": " + handler.getClass().getName());
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(getId() + ": No profile handler registered for request path " + requestPath);
            }
        }
        return handler;
    }

    /**
     * Gets the registered profile handlers.
     * 
     * @return registered profile handlers
     */
    public Map<String, AbstractRequestURIMappedProfileHandler> getProfileHandlers() {
        return profileHandlers;
    }

    /**
     * Gets the authentication handler appropriate for the given loging context. The mechanism used to determine the
     * "appropriate" handler is implementation specific.
     * 
     * @param loginContext current login context
     * 
     * @return authentication method URI and handler appropriate for given login context
     */
    public Pair<String, AuthenticationHandler> getAuthenticationHandler(LoginContext loginContext) {
        if (log.isDebugEnabled()) {
            log.debug(getId() + ": Looking up authentication method for relying party "
                    + loginContext.getRelyingPartyId());
        }
        List<String> requestedMethods = loginContext.getRequestedAuthenticationMethods();
        if (requestedMethods != null) {
            AuthenticationHandler candidateHandler;
            for (String requestedMethod : requestedMethods) {
                if (log.isDebugEnabled()) {
                    log.debug(getId() + ": Checking for authentication handler for method " + requestedMethod
                            + " which was requested for relying party " + loginContext.getRelyingPartyId());
                }
                candidateHandler = authenticationHandlers.get(requestedMethod);
                if (candidateHandler != null) {
                    if (log.isDebugEnabled()) {
                        log.debug(getId() + ": Authentication handler for method " + requestedMethod
                                + " for relying party " + loginContext.getRelyingPartyId()
                                + " found.  Checking if it meets othe criteria.");
                    }
                    if(loginContext.getPassiveAuth() && !candidateHandler.supportsPassive()){
                        if (log.isDebugEnabled()) {
                            log.debug(getId() + ": Authentication handler for method " + requestedMethod
                                    + " for relying party " + loginContext.getRelyingPartyId()
                                    + " does not meet required support for passive auth.  Skipping it");
                        }
                        continue;
                    }
                    
                    if (log.isDebugEnabled()) {
                        log.debug(getId() + ": Authentication handler for method " + requestedMethod
                                + " for relying party " + loginContext.getRelyingPartyId()
                                + " meets all requirements, using it.");
                    }
                    return new Pair<String, AuthenticationHandler>(requestedMethod, candidateHandler);
                }
            }
        } else {
            log.error(getId() + ": No requested authentication methods for relying party "
                    + loginContext.getRelyingPartyId());
        }

        return null;
    }

    /**
     * Gets the registered authentication handlers.
     * 
     * @return registered authentication handlers
     */
    public Map<String, AuthenticationHandler> getAuthenticationHandlers() {
        return authenticationHandlers;
    }

    /** {@inheritDoc} */
    protected void newContextCreated(ApplicationContext newServiceContext) {
        if (log.isDebugEnabled()) {
            log.debug(getId() + ": Loading new configuration into service");
        }
        Lock writeLock = getReadWriteLock().writeLock();
        writeLock.lock();
        loadNewErrorHandler(newServiceContext);
        loadNewProfileHandlers(newServiceContext);
        loadNewAuthenticationHandlers(newServiceContext);
        writeLock.unlock();
    }

    /**
     * Reads the new error handler from the newly created application context and loads it into this manager.
     * 
     * @param newServiceContext newly created application context
     */
    protected void loadNewErrorHandler(ApplicationContext newServiceContext) {
        String[] errorBeanNames = newServiceContext.getBeanNamesForType(AbstractErrorHandler.class);
        if (log.isDebugEnabled()) {
            log.debug(getId() + ": Loading " + errorBeanNames.length + " new error handler.");
        }

        errorHandler = (AbstractErrorHandler) newServiceContext.getBean(errorBeanNames[0]);
        if (log.isDebugEnabled()) {
            log.debug(getId() + ": Loaded new error handler of type: " + errorHandler.getClass().getName());
        }
    }

    /**
     * Reads the new profile handlers from the newly created application context and loads it into this manager.
     * 
     * @param newServiceContext newly created application context
     */
    protected void loadNewProfileHandlers(ApplicationContext newServiceContext) {
        String[] profileBeanNames = newServiceContext.getBeanNamesForType(AbstractRequestURIMappedProfileHandler.class);
        if (log.isDebugEnabled()) {
            log.debug(getId() + ": Loading " + profileBeanNames.length + " new profile handlers.");
        }

        profileHandlers.clear();
        AbstractRequestURIMappedProfileHandler<?,?> profileHandler;
        for (String profileBeanName : profileBeanNames) {
            profileHandler = (AbstractRequestURIMappedProfileHandler) newServiceContext.getBean(profileBeanName);
            for (String requestPath : profileHandler.getRequestPaths()) {
                profileHandlers.put(requestPath, profileHandler);
                if (log.isDebugEnabled()) {
                    log.debug(getId() + ": Loaded profile handler of type "
                                    + profileHandler.getClass().getName() + " handling requests to request path "
                                    + requestPath);
                }
            }
        }
    }

    /**
     * Reads the new authentication handlers from the newly created application context and loads it into this manager.
     * 
     * @param newServiceContext newly created application context
     */
    protected void loadNewAuthenticationHandlers(ApplicationContext newServiceContext) {
        String[] authnBeanNames = newServiceContext.getBeanNamesForType(AuthenticationHandler.class);
        if (log.isDebugEnabled()) {
            log.debug(getId() + ": Loading " + authnBeanNames.length + " new authentication handlers.");
        }

        authenticationHandlers.clear();
        AuthenticationHandler authnHandler;
        for (String authnBeanName : authnBeanNames) {
            authnHandler = (AuthenticationHandler) newServiceContext.getBean(authnBeanName);
            if (log.isDebugEnabled()) {
                log.debug(getId() + ": Loading authentication handler of type "
                        + authnHandler.getClass().getName() + " supporting authentication methods: "
                        + authnHandler.getSupportedAuthenticationMethods());
            }
            for (String authnMethod : authnHandler.getSupportedAuthenticationMethods()) {
                authenticationHandlers.put(authnMethod, authnHandler);
            }
        }
    }
}