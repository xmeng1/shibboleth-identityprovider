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

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

/**
 * Authenticate a username and password against a JAAS source.
 * 
 * This {@link AuthenticationHandler} requires a JSP to collect a username and password from the user. It also requires
 * a JAAS configuration file to validate the username and password.
 * 
 * If an Authentication Context Class or DeclRef URI is not specified, it will default to
 * "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".
 */
public class UsernamePasswordAuthenticationHandler extends AbstractAuthenticationHandler {

    /** Key in an HttpSession for the JAAS configuration name. */
    public static final String JAAS_CONFIG_NAME = "UsernamePasswordAuthenticationHandler.JAAS_CONFIG_NAME";

    /** Key in an HttpSession for the username. */
    public static final String USERNAME = "UsernamePasswordAuthenticationHandler.USERNAME";

    /** Key in an HttpSession for the authentication instant. */
    public static final String AUTHN_INSTANT = "UsernamePasswordAuthenticationHandler.AUTHN_INSTANT";

    private static final Logger log = Logger.getLogger(UsernamePasswordAuthenticationHandler.class);

    /** The name of the JAAS Configuration to use. */
    protected String jaasConfigurationName;

    /** The name of the login page. */
    protected String loginURL;

    /** The authN duration, in seconds. */
    protected int authnDuration;

    /** The URI of the AuthnContextDeclRef or the AuthnContextClass */
    private String authnMethodURI = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

    public UsernamePasswordAuthenticationHandler() {
    }

    /** @{inheritDoc} */
    public boolean supportsPassive() {
        return true;
    }

    /** @{inheritDoc} */
    public boolean supportsForceAuthentication() {
        return true;
    }

    /** {@inheritDoc} */
    public void login(
            final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) {

//        HttpSession session = httpRequest.getSession();
//
//        // these fields will need to be set, regardless of how we branch.
//        loginContext.setAuthenticationAttempted();
//        loginContext.setAuthenticationMethod(authnMethodURI);
//
//        // If forceAuth is set, we must forward to the login JSP.
//        if (loginContext.getForceAuth()) {
//
//            if (loginContext.getPassiveAuth()) {
//                log
//                        .error("UsernamePasswordAuthenticationHandler: Unable to authenticate user: both forceAuthN and passiveAuthnN are set in the login context.");
//                redirectControl(loginContext.getAuthenticationEngineURL(), "AuthenticationManager", httpRequest,
//                        httpResponse);
//            }
//
//            session.setAttribute(JAAS_CONFIG_NAME, jaasConfigurationName);
//            redirectControl(loginURL, "login page", httpRequest, httpResponse);
//        }
//
//        // If the user has already been authenticated, forceAuth is not set,
//        // and the authentication hasn't expired, then populate the LoginCtx
//        // and return control to the AuthenticationManager.
//        // Otherwise, redirect the user to loginJSPURL to collect a username and
//        // password.
//
//        // implementation note: There is a race condition here, but I'm not sure
//        // how to avoid it. I need a way to instantiate a lock in the session to
//        // protect the
//        // username and authnInstant fields.
//
//        Object o = session.getAttribute(USERNAME);
//        if (!(o instanceof String)) {
//            log
//                    .debug("UsernamePasswordAuthenticationHandler: Username attribute found in HttpSession, but it is not a String.");
//
//            redirectControl(loginURL, "login page", httpRequest, httpResponse);
//        }
//
//        String username = (String) o;
//
//        o = session.getAttribute(AUTHN_INSTANT);
//        if (!(o instanceof DateTime)) {
//            log.debug("UsernamePasswordAuthenticationHandler: AuthnInstant attribute found in HttpSession for user "
//                    + username + ", but it is not a DateTime.");
//
//            redirectControl(loginURL, "login page", httpRequest, httpResponse);
//        }
//
//        DateTime authnInstant = (DateTime) o;
//        DateTime authnExpires = authnInstant.plusSeconds(authnDuration);
//        DateTime now = new DateTime();
//        if (now.isAfter(authnExpires)) {
//            log.info("UsernamePasswordAuthenticationHandler: Authentication has expired for user " + username);
//            redirectControl(loginURL, "login page", httpRequest, httpResponse);
//        }
//
//        // the current authentication information is still valid, so return it.
//        loginContext.setPrincipalAuthenticated(true);
//        loginContext.setPrincipalName(username);
//        loginContext.setAuthenticationInstant(authnInstant);
//
//        // XXX: adjust for the appropriate units?
//        loginContext.setAuthenticationDuration(authnDuration);

    }

    /** {@inheritDoc} */
    public void logout(final HttpServletRequest request, final HttpServletResponse response, String principal) {
        return;
    }

    /**
     * Set the name of the JAAS Configuration to use for user authentication.
     * 
     * @param configurationName The name of the JAAS Configuration entry.
     */
    public void setJAASConfigurationName(String configurationName) {
        jaasConfigurationName = configurationName;
    }

    /**
     * Get the name of the JAAS Configuraiton to use for user authentication.
     * 
     * @return The name of the JAAS Configuration entry.
     */
    public String getJAASConfiguraitonName() {
        return jaasConfigurationName;
    }

    /**
     * Set the duration of the authentication.
     * 
     * @param duration The duration, in seconds, of the authentication.
     */
    public void setAuthNDuration(int duration) {
        authnDuration = duration;
    }

    /**
     * Get the duration of the authentication.
     * 
     * @return The duration, in seconds, of the authentication.
     */
    public int getAuthNDuration() {
        return authnDuration;
    }

    /**
     * Return control to the AuthNManager.
     * 
     * @param url The URL to which control should be redirected.
     * @param urlDescription An optional textual description of <code>url</code>.
     * @param request The HttpServletRequest.
     * @param response The HttpServletResponse.
     */
    protected void redirectControl(String url, String urlDescription, final HttpServletRequest request,
            final HttpServletResponse response) {

        try {
            RequestDispatcher dispatcher = request.getRequestDispatcher(url);
            dispatcher.forward(request, response);
        } catch (ServletException ex) {
            log.error("UsernamePasswordAuthenticationHandler: Error returning control to " + urlDescription, ex);
        } catch (IOException ex) {
            log.error("UsernamePasswordAuthenticationHandler: Error returning control to " + urlDescription, ex);
        }
    }
}
