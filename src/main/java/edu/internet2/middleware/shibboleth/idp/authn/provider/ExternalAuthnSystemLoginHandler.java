/*
 * Copyright 2011 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.authn.provider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.util.URLBuilder;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * A login handler meant to bridge between the IdP and an external, web-based, authentication service.
 * 
 * This login handler will redirect the user-agent to a context-relative path and include the following query
 * parameters: {@link #FORCE_AUTHN_PARAM}, {@link #PASSIVE_AUTHN_PARAM}, {@link #AUTHN_METHOD_PARAM},
 * {@link #RETURN_URL_PARAM}, {@link #RELYING_PARTY_PARAM}.
 * 
 * The external authentication service must be configured to protect the page to which the user-agent is authenticated.
 * This external service must populate the REMOTE_USER header with the principal name of the authenticated user. The
 * external authentication service may also indicate which authentication method it actually performed by populating the
 * HTTP header name {@value #AUTHN_METHOD_PARAM}.
 */
public class ExternalAuthnSystemLoginHandler extends AbstractLoginHandler {

    /**
     * Query parameter that indicates whether the authentication request requires forced authentication. Parameter Name:
     * * {@value}
     */
    public static final String FORCE_AUTHN_PARAM = "forceAuthn";

    /**
     * Query parameter that indicates whether the authentication requires passive authentication. Parameter Name: * * *
     * * {@value}
     */
    public static final String PASSIVE_AUTHN_PARAM = "isPassive";

    /** Query parameter that provides which authentication method should be attempted. Parameter Name: {@value} */
    public static final String AUTHN_METHOD_PARAM = "authnMethod";

    /**
     * Query parameter that provides the entity ID of the relying party that is requesting authentication. Parameter
     * Name: {@value}
     */
    public static final String RELYING_PARTY_PARAM = "relyingParty";

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(RemoteUserLoginHandler.class);

    /** The context-relative path to the SSO-protected Servlet. Default value: {@value} */
    private String protectedPath = "/Authn/External";

    /** Static query parameters sent to the SSO-protected Servlet. */
    private Map<String, String> queryParameters;

    /** Constructor. */
    public ExternalAuthnSystemLoginHandler() {
        super();
        queryParameters = new HashMap<String, String>();
    }

    /**
     * Get context-relative path to the SSO-protected Servlet.
     * 
     * @return context-relative path to the SSO-protected Servlet
     */
    public String getProtectedPath() {
        return protectedPath;
    }

    /**
     * Set context-relative path to the SSO-protected Servlet. The given path may not contain fragments and/or query
     * params.
     * 
     * @param path context-relative path to the SSO-protected Servlet, may not be null or empty
     */
    public void setProtectedPath(String path) {
        String trimmedPath = DatatypeHelper.safeTrimOrNullString(path);
        if (trimmedPath == null) {
            throw new IllegalArgumentException("Protected path may not be null or empty");
        }

        if (trimmedPath.contains("?")) {
            throw new IllegalArgumentException("Protected path may not include query parameters");
        }

        if (trimmedPath.contains("#")) {
            throw new IllegalArgumentException("Protected path may not include document fragements");
        }

        protectedPath = trimmedPath;
    }

    /**
     * Gets the immutable set of query parameters sent to the SSO-protected Servlet.
     * 
     * @return immutable set of query parameters sent to the SSO-protected Servlet, never null
     */
    public Map<String, String> getQueryParameters() {
        return queryParameters;
    }

    /**
     * Sets the query parameters that will be sent to the SSO-protected Servlet.
     * 
     * @param params query parameters that will be sent to the SSO-protected Servlet, maybe null
     */
    public void setQueryParameters(Map<String, String> params) {
        HashMap<String, String> newParams = new HashMap<String, String>();

        String trimmedKeyName;
        for (Entry<String, String> param : params.entrySet()) {
            trimmedKeyName = DatatypeHelper.safeTrimOrNullString(param.getKey());
            if (trimmedKeyName != null) {
                newParams.put(trimmedKeyName, DatatypeHelper.safeTrimOrNullString(param.getValue()));
            }
        }

        queryParameters = Collections.unmodifiableMap(newParams);
    }

    /** {@inheritDoc} */
    public void login(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {

        // forward control to the servlet.
        try {
            String profileUrl = HttpServletHelper.getContextRelativeUrl(httpRequest, protectedPath).buildURL();

            log.debug("Redirecting to {}", profileUrl);
            httpResponse.sendRedirect(profileUrl);
            return;
        } catch (IOException ex) {
            log.error("Unable to redirect to remote user authentication servlet.", ex);
        }
    }

    /**
     * Builds the URL that redirects to the external authentication service.
     * 
     * @param httpRequest current HTTP request
     * 
     * @return URL to which to redirect the user-agent
     */
    protected String buildRedirectUrl(HttpServletRequest httpRequest) {
        URLBuilder urlBuilder = new URLBuilder();
        urlBuilder.setScheme(httpRequest.getScheme());
        urlBuilder.setHost(httpRequest.getServerName());
        urlBuilder.setPort(httpRequest.getServerPort());

        StringBuilder pathBuilder = new StringBuilder();
        if (!"".equals(httpRequest.getContextPath())) {
            pathBuilder.append(httpRequest.getContextPath());
        }
        if (!protectedPath.startsWith("/")) {
            pathBuilder.append("/");
        }
        pathBuilder.append(protectedPath);
        urlBuilder.setPath(pathBuilder.toString());

        urlBuilder.getQueryParams().addAll(buildQueryParameters(httpRequest));

        return urlBuilder.buildURL();
    }

    /**
     * Builds the query parameters that will be sent to the external authentication service.
     * 
     * @param httpRequest current HTTP request
     * 
     * @return query parameters to be sent to the external authentication service
     */
    protected List<Pair<String, String>> buildQueryParameters(HttpServletRequest httpRequest) {
        LoginContext loginContext = HttpServletHelper.getLoginContext(httpRequest);

        ArrayList<Pair<String, String>> params = new ArrayList<Pair<String, String>>();

        for (Entry<String, String> staticParam : queryParameters.entrySet()) {
            params.add(new Pair<String, String>(staticParam.getKey(), staticParam.getValue()));
        }

        if (loginContext.isForceAuthRequired()) {
            params.add(new Pair<String, String>(FORCE_AUTHN_PARAM, Boolean.TRUE.toString()));
        } else {
            params.add(new Pair<String, String>(FORCE_AUTHN_PARAM, Boolean.FALSE.toString()));
        }

        if (loginContext.isPassiveAuthRequired()) {
            params.add(new Pair<String, String>(PASSIVE_AUTHN_PARAM, Boolean.TRUE.toString()));
        } else {
            params.add(new Pair<String, String>(PASSIVE_AUTHN_PARAM, Boolean.FALSE.toString()));
        }

        params.add(new Pair<String, String>(AUTHN_METHOD_PARAM, loginContext.getAttemptedAuthnMethod()));

        params.add(new Pair<String, String>(RELYING_PARTY_PARAM, loginContext.getRelyingPartyId()));

        return params;
    }
}