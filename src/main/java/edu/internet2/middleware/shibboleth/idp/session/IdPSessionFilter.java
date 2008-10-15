/*
 * Copyright 2008 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.session;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;

/**
 * A filter that adds the current users {@link Session} the request, if the user has a session.
 */
public class IdPSessionFilter implements Filter {

    /** Class Logger. */
    private final Logger log = LoggerFactory.getLogger(IdPSessionFilter.class);

    /** Whether the client must always come back from the same address. */
    private boolean consistentAddress;

    /** IdP session manager. */
    private SessionManager<Session> sessionManager;

    /** {@inheritDoc} */
    public void destroy() {

    }

    /** {@inheritDoc} */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException,
            ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        Cookie sessionCookie = getIdPSessionCookie(httpRequest);
        Session idpSession = validateCookie(sessionCookie, httpRequest);
        if (idpSession != null) {
            log.trace("Updating IdP session activity time and adding session object to the request");
            idpSession.setLastActivityInstant(new DateTime());
            MDC.put("idpSessionId", idpSession.getSessionID());
            httpRequest.setAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE, idpSession);
        }

        filterChain.doFilter(request, response);
    }

    /** {@inheritDoc} */
    public void init(FilterConfig filterConfig) throws ServletException {
        String sessionManagerId = filterConfig.getInitParameter("sessionManagedId");
        if (DatatypeHelper.isEmpty(sessionManagerId)) {
            sessionManagerId = "shibboleth.SessionManager";
        }

        sessionManager = (SessionManager<Session>) filterConfig.getServletContext().getAttribute(sessionManagerId);

        String consistentAddressParam = filterConfig.getInitParameter("ensureConsistentClientAddress");
        if (DatatypeHelper.isEmpty(consistentAddressParam)) {
            consistentAddress = true;
        } else {
            consistentAddress = Boolean.parseBoolean(consistentAddressParam);
        }
    }

    /**
     * Gets the IdP session cookie from the current request, if the user currently has a session.
     * 
     * @param httpRequest current HTTP request
     * 
     * @return the user's current IdP session cookie, if they have a current session, otherwise null
     */
    protected Cookie getIdPSessionCookie(HttpServletRequest httpRequest) {
        log.trace("Attempting to retrieve IdP session cookie.");
        Cookie[] requestCookies = httpRequest.getCookies();

        if (requestCookies != null) {
            for (Cookie requestCookie : requestCookies) {
                if (DatatypeHelper.safeEquals(requestCookie.getName(), AuthenticationEngine.IDP_SESSION_COOKIE_NAME)) {
                    log.trace("Found IdP session cookie.");
                    return requestCookie;
                }
            }
        }

        return null;
    }

    /**
     * Validates the given session cookie against the associated session.
     * 
     * @param sessionCookie the session cookie
     * @param httpRequest the current HTTP request
     * 
     * @return the session against which the cookie was validated
     */
    protected Session validateCookie(Cookie sessionCookie, HttpServletRequest httpRequest) {
        if (sessionCookie == null) {
            return null;
        }

        // index 0: remote address
        // index 1: session ID
        // index 2: Base64(HMAC(index 0 + index 1))
        String[] valueComponents = sessionCookie.getValue().split("\\|");
        byte[] remoteAddressBytes = Base64.decode(valueComponents[0]);
        byte[] sessionIdBytes = Base64.decode(valueComponents[1]);
        byte[] signatureBytes = Base64.decode(valueComponents[2]);

        if (consistentAddress) {
            String remoteAddress = new String(remoteAddressBytes);
            if (!httpRequest.getRemoteAddr().equals(remoteAddress)) {
                log.error("Client sent a cookie from addres {} but the cookie was issued to address {}", httpRequest
                        .getRemoteAddr(), remoteAddress);
                return null;
            }
        }

        String sessionId = new String(sessionIdBytes);
        Session userSession = sessionManager.getSession(sessionId);

        if (userSession != null) {
            SecretKey signingKey = userSession.getSessionSecretKey();
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(signingKey);
                mac.update(remoteAddressBytes);
                mac.update(sessionIdBytes);
                byte[] signature = mac.doFinal();

                if (!Arrays.equals(signature, signatureBytes)) {
                    log.error("Session cookie signature did not match, the session cookie has been tampered with");
                    return null;
                }
            } catch (GeneralSecurityException e) {
                log.error("Unable to computer over session cookie material", e);
            }
        } else {
            log.debug("No session associated with session ID {} - session must have timed out",
                            valueComponents[1]);
        }
        return userSession;
    }
}