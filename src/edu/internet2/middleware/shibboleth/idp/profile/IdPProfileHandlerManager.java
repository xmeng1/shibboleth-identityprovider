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
import java.util.Map;
import java.util.concurrent.locks.Lock;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import edu.internet2.middleware.shibboleth.common.config.BaseReloadableService;
import edu.internet2.middleware.shibboleth.common.profile.AbstractErrorHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractRequestURIMappedProfileHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;

/**
 * Implementation of a {@link ProfileHandlerManager} that maps the request path, without the servlet context, to a
 * profile handler and adds support for authentication handlers.
 */
public class IdPProfileHandlerManager extends BaseReloadableService implements ProfileHandlerManager {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(IdPProfileHandlerManager.class);

    /** Handler used for errors. */
    private AbstractErrorHandler errorHandler;

    /** Map of request paths to profile handlers. */
    private Map<String, AbstractRequestURIMappedProfileHandler> profileHandlers;

    /** Map of authentication methods to login handlers. */
    private Map<String, LoginHandler> loginHandlers;

    /** Constructor. */
    public IdPProfileHandlerManager() {
        super();
        profileHandlers = new HashMap<String, AbstractRequestURIMappedProfileHandler>();
        loginHandlers = new HashMap<String, LoginHandler>();
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
        log.debug("{}: Looking up profile handler for request path: {}", getId(), requestPath);

        Lock readLock = getReadWriteLock().readLock();
        readLock.lock();
        handler = profileHandlers.get(requestPath);
        readLock.unlock();

        if (handler != null) {
            log.debug("{}: Located profile handler of the following type for the request path: {}", getId(), handler
                    .getClass().getName());
        } else {
            log.debug("{}: No profile handler registered for request path {}", getId(), requestPath);
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
     * Gets the registered authentication handlers.
     * 
     * @return registered authentication handlers
     */
    public Map<String, LoginHandler> getLoginHandlers() {
        return loginHandlers;
    }

    /** {@inheritDoc} */
    protected void onNewContextCreated(ApplicationContext newServiceContext) {
        log.debug("{}: Loading new configuration into service", getId());
        Lock writeLock = getReadWriteLock().writeLock();
        try {
            writeLock.lock();
            loadNewErrorHandler(newServiceContext);
            loadNewProfileHandlers(newServiceContext);
            loadNewAuthenticationHandlers(newServiceContext);
        } catch (Exception e) {
            log.error("Error loading information from new context", e);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Reads the new error handler from the newly created application context and loads it into this manager.
     * 
     * @param newServiceContext newly created application context
     */
    protected void loadNewErrorHandler(ApplicationContext newServiceContext) {
        String[] errorBeanNames = newServiceContext.getBeanNamesForType(AbstractErrorHandler.class);
        log.debug("{}: Loading {} new error handler.", getId(), errorBeanNames.length);

        errorHandler = (AbstractErrorHandler) newServiceContext.getBean(errorBeanNames[0]);
        log.debug("{}: Loaded new error handler of type: {}", getId(), errorHandler.getClass().getName());
    }

    /**
     * Reads the new profile handlers from the newly created application context and loads it into this manager.
     * 
     * @param newServiceContext newly created application context
     */
    protected void loadNewProfileHandlers(ApplicationContext newServiceContext) {
        String[] profileBeanNames = newServiceContext.getBeanNamesForType(AbstractRequestURIMappedProfileHandler.class);
        log.debug("{}: Loading {} new profile handlers.", getId(), profileBeanNames.length);

        profileHandlers.clear();
        AbstractRequestURIMappedProfileHandler<?, ?> profileHandler;
        for (String profileBeanName : profileBeanNames) {
            profileHandler = (AbstractRequestURIMappedProfileHandler) newServiceContext.getBean(profileBeanName);
            for (String requestPath : profileHandler.getRequestPaths()) {
                profileHandlers.put(requestPath, profileHandler);
                log.debug("{}: Loaded profile handler for handling requests to request path {}", getId(), requestPath);
            }
        }
    }

    /**
     * Reads the new authentication handlers from the newly created application context and loads it into this manager.
     * 
     * @param newServiceContext newly created application context
     */
    protected void loadNewAuthenticationHandlers(ApplicationContext newServiceContext) {
        String[] authnBeanNames = newServiceContext.getBeanNamesForType(LoginHandler.class);
        log.debug("{}: Loading {} new authentication handlers.", getId(), authnBeanNames.length);

        loginHandlers.clear();
        LoginHandler authnHandler;
        for (String authnBeanName : authnBeanNames) {
            authnHandler = (LoginHandler) newServiceContext.getBean(authnBeanName);
            log.debug("{}: Loading authentication handler of type supporting authentication methods: {}", getId(),
                    authnHandler.getSupportedAuthenticationMethods());

            for (String authnMethod : authnHandler.getSupportedAuthenticationMethods()) {
                loginHandlers.put(authnMethod, authnHandler);
            }
        }
    }
}