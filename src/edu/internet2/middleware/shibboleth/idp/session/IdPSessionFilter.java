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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.session.SessionManager;

/**
 * A filter that adds the current users {@link Session} the request, if the user has a session.
 */
public class IdPSessionFilter implements Filter {

    /** Name of the IdP Cookie containing the IdP session ID. */
    public static final String IDP_SESSION_COOKIE_NAME = "_idp_session";

    /** IdP session manager. */
    private SessionManager<Session> sessionManager;

    /** {@inheritDoc} */
    public void destroy() {

    }

    /** {@inheritDoc} */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException,
            ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        Session idpSession = null;
        Cookie idpSessionCookie = getIdPSessionCookie(httpRequest);
        if (idpSessionCookie != null) {
            idpSession = sessionManager.getSession(idpSessionCookie.getValue());
            if (idpSession != null) {
                idpSession.setLastActivityInstant(new DateTime());
                httpRequest.setAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE, idpSession);
            }
        }

        addIdPSessionCookieToResponse(httpRequest, httpResponse, idpSession);

        filterChain.doFilter(request, response);
    }

    /** {@inheritDoc} */
    public void init(FilterConfig filterConfig) throws ServletException {
        sessionManager = (SessionManager<Session>) filterConfig.getServletContext().getAttribute("sessionManager");
    }

    /**
     * Gets the IdP session cookie from the current request, if the user currently has a session.
     * 
     * @param request current HTTP request
     * 
     * @return the user's current IdP session cookie, if they have a current session, otherwise null
     */
    protected Cookie getIdPSessionCookie(HttpServletRequest request) {
        Cookie[] requestCookies = request.getCookies();

        if (requestCookies != null) {
            for (Cookie requestCookie : requestCookies) {
                if (DatatypeHelper.safeEquals(requestCookie.getDomain(), request.getLocalName())
                        && DatatypeHelper.safeEquals(requestCookie.getPath(), request.getContextPath())
                        && DatatypeHelper.safeEquals(requestCookie.getName(), IDP_SESSION_COOKIE_NAME)) {
                    return requestCookie;
                }
            }
        }

        return null;
    }

    /**
     * Adds a cookie, containing the user's IdP session ID, to the response.
     * 
     * @param request current HTTP request
     * @param response current HTTP response
     * @param userSession user's currentSession
     */
    protected void addIdPSessionCookieToResponse(HttpServletRequest request, HttpServletResponse response,
            Session userSession) {
        Session currentSession = userSession;
        if (currentSession == null) {
            currentSession = (Session) request.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
            if (currentSession == null) {
                currentSession = (Session) request.getSession().getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
            }
        }

        if (currentSession != null) {
            Cookie sessionCookie = new Cookie(IDP_SESSION_COOKIE_NAME, userSession.getSessionID());
            sessionCookie.setDomain(request.getLocalName());
            sessionCookie.setPath(request.getContextPath());
            sessionCookie.setSecure(false);

            int maxAge = (int) (userSession.getInactivityTimeout() / 1000);
            sessionCookie.setMaxAge(maxAge);

            response.addCookie(sessionCookie);
        }
    }
}