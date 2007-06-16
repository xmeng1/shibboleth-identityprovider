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

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.encoding.MessageEncoder;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.ShibbolethSSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.ShibbolethSSOLoginContext;

/** Shibboleth SSO request profile handler. */
public class ShibbolethSSOProfileHandler extends AbstractSAML1ProfileHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(ShibbolethSSOProfileHandler.class);

    /** Builder of AuthenticationStatement objects. */
    private SAMLObjectBuilder<AuthenticationStatement> authnStatementBuilder;

    /** URL of the authentication manager servlet. */
    private String authenticationManagerPath;

    /** Message encoder binding URI. */
    private String encodingBinding;

    /**
     * Constructor.
     * 
     * @param authnManagerPath path to the authentication manager servlet
     * @param encoder URI of the encoding binding
     * 
     * @throws IllegalArgumentException thrown if either the authentication manager path or encoding binding URI are
     *             null or empty
     */
    public ShibbolethSSOProfileHandler(String authnManagerPath, String encoder) {
        if (DatatypeHelper.isEmpty(authnManagerPath) || DatatypeHelper.isEmpty(encoder)) {
            throw new IllegalArgumentException("Authentication manager path and encoder binding URI may not be null");
        }

        authenticationManagerPath = authnManagerPath;
        encodingBinding = encoder;

        authnStatementBuilder = (SAMLObjectBuilder<AuthenticationStatement>) getBuilderFactory().getBuilder(
                AuthenticationStatement.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Convenience method for getting the SAML 1 AuthenticationStatement builder.
     * 
     * @return SAML 1 AuthenticationStatement builder
     */
    public SAMLObjectBuilder<AuthenticationStatement> getAuthenticationStatementBuilder() {
        return authnStatementBuilder;
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:shibboleth:request:sso";
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response)
            throws ProfileException {

        HttpSession httpSession = ((HttpServletRequest) request.getRawRequest()).getSession(true);
        if (httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY) == null) {
            performAuthentication(request, response);
        } else {
            completeAuthenticationRequest(request, response);
        }
    }

    /**
     * Creates a {@link LoginContext} an sends the request off to the AuthenticationManager to begin the process of
     * authenticating the user.
     * 
     * @param request current request
     * @param response current response
     * 
     * @throws ProfileException thrown if there is a problem creating the login context and transferring control to the
     *             authentication manager
     */
    protected void performAuthentication(ProfileRequest<ServletRequest> request,
            ProfileResponse<ServletResponse> response) throws ProfileException {

        HttpServletRequest httpRequest = (HttpServletRequest) request.getRawRequest();
        HttpServletResponse httpResponse = (HttpServletResponse) response.getRawResponse();
        HttpSession httpSession = httpRequest.getSession(true);

        LoginContext loginContext = buildLoginContext(httpRequest);
        httpSession.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);

        try {
            RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(authenticationManagerPath);
            dispatcher.forward(httpRequest, httpResponse);
        } catch (IOException ex) {
            log.error("Error forwarding Shibboleth SSO request to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding Shibboleth SSO request to AuthenticationManager", ex);
        } catch (ServletException ex) {
            log.error("Error forwarding Shibboleth SSO request to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding Shibboleth SSO request to AuthenticationManager", ex);
        }
    }

    /**
     * Creates a response to the Shibboleth SSO and sends the user, with response in tow, back to the relying party
     * after they've been authenticated.
     * 
     * @param request current request
     * @param response current response
     * 
     * @throws ProfileException thrown if the response can not be created and sent back to the relying party
     */
    protected void completeAuthenticationRequest(ProfileRequest<ServletRequest> request,
            ProfileResponse<ServletResponse> response) throws ProfileException {
        HttpSession httpSession = ((HttpServletRequest) request.getRawRequest()).getSession(true);

        ShibbolethSSOLoginContext loginContext = (ShibbolethSSOLoginContext) httpSession
                .getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        httpSession.removeAttribute(LoginContext.LOGIN_CONTEXT_KEY);

        ShibbolethSSORequestContext requestContext = buildRequestContext(loginContext, request, response);

        Response samlResponse;
        try {
            if (!loginContext.isPrincipalAuthenticated()) {
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "User failed authentication"));
                throw new ProfileException("User failed authentication");
            }

            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAuthenticationStatement(requestContext));
            if (requestContext.getProfileConfiguration().includeAttributeStatement()) {
                statements
                        .add(buildAttributeStatement(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"));
            }

            samlResponse = buildResponse(requestContext, statements);
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext);
        }

        requestContext.setSamlResponse(samlResponse);
        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Creates a login context from the incoming HTTP request.
     * 
     * @param request current HTTP request
     * 
     * @return the constructed login context
     * 
     * @throws ProfileException thrown if the incomming request did not contain a providerId, shire, and target
     *             parameter
     */
    protected ShibbolethSSOLoginContext buildLoginContext(HttpServletRequest request) throws ProfileException {
        ShibbolethSSOLoginContext loginContext = new ShibbolethSSOLoginContext();

        try {
            String providerId = DatatypeHelper.safeTrimOrNullString(request.getParameter("providerId"));
            if (providerId == null) {
                log.error("No providerId parameter in Shibboleth SSO request");
                throw new ProfileException("No providerId parameter in Shibboleth SSO request");
            }
            loginContext.setRelyingParty(URLDecoder.decode(providerId, "UTF-8"));

            String acs = DatatypeHelper.safeTrimOrNullString(request.getParameter("shire"));
            if (acs == null) {
                log.error("No shire parameter in Shibboleth SSO request");
                throw new ProfileException("No shire parameter in Shibboleth SSO request");
            }
            loginContext.setSpAssertionConsumerService(URLDecoder.decode(acs, "UTF-8"));

            String target = DatatypeHelper.safeTrimOrNullString(request.getParameter("target"));
            if (target == null) {
                log.error("No target parameter in Shibboleth SSO request");
                throw new ProfileException("No target parameter in Shibboleth SSO request");
            }
            loginContext.setSpTarget(URLDecoder.decode(target, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            // UTF-8 encoding required to be supported by all JVMs.
        }

        loginContext.setAuthenticationEngineURL(authenticationManagerPath);
        loginContext.setProfileHandlerURL(request.getRequestURI());
        return loginContext;
    }

    /**
     * Creates an authentication request context from the current environmental information.
     * 
     * @param loginContext current login context
     * @param request current request
     * @param response current response
     * 
     * @return created authentication request context
     */
    protected ShibbolethSSORequestContext buildRequestContext(ShibbolethSSOLoginContext loginContext,
            ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response) {
        ShibbolethSSORequestContext requestContext = new ShibbolethSSORequestContext(request, response);

        requestContext.setLoginContext(loginContext);

        requestContext.setPrincipalName(loginContext.getPrincipalName());

        requestContext.setPrincipalAuthenticationMethod(loginContext.getAuthenticationMethod());

        String relyingPartyId = loginContext.getRelyingPartyId();

        requestContext.setRelyingPartyId(relyingPartyId);

        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
        requestContext.setRelyingPartyConfiguration(rpConfig);

        requestContext.setRelyingPartyRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setAssertingPartyId(requestContext.getRelyingPartyConfiguration().getProviderId());

        requestContext.setAssertingPartyRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setProfileConfiguration((ShibbolethSSOConfiguration) rpConfig
                .getProfileConfiguration(ShibbolethSSOConfiguration.PROFILE_ID));

        return requestContext;
    }

    /**
     * Builds the authentication statement for the authenticated principal.
     * 
     * @param requestContext current request context
     * 
     * @return the created statement
     * 
     * @throws ProfileException thrown if the authentication statement can not be created
     */
    protected AuthenticationStatement buildAuthenticationStatement(ShibbolethSSORequestContext requestContext)
            throws ProfileException {
        ShibbolethSSOLoginContext loginContext = requestContext.getLoginContext();

        AuthenticationStatement statement = getAuthenticationStatementBuilder().buildObject();
        statement.setAuthenticationInstant(loginContext.getAuthenticationInstant());
        statement.setAuthenticationMethod(loginContext.getAuthenticationMethod());

        // TODO
        statement.setSubjectLocality(null);

        Subject statementSubject = buildSubject(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches");
        statement.setSubject(statementSubject);

        return statement;
    }

    /**
     * Encodes the request's SAML response and writes it to the servlet response.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if no message encoder is registered for this profiles binding
     */
    protected void encodeResponse(ShibbolethSSORequestContext requestContext) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Encoding response to SAML request from relying party " + requestContext.getRelyingPartyId());
        }
        MessageEncoder<ServletResponse> encoder = getMessageEncoderFactory().getMessageEncoder(encodingBinding);
        if (encoder == null) {
            throw new ProfileException("No response encoder was registered for binding type: " + encodingBinding);
        }

        super.populateMessageEncoder(encoder);
        encoder.setResponse(requestContext.getProfileResponse().getRawResponse());
        encoder.setSamlMessage(requestContext.getSamlResponse());
        requestContext.setMessageEncoder(encoder);

        try {
            encoder.encode();
        } catch (BindingException e) {
            throw new ProfileException("Unable to encode response to relying party: "
                    + requestContext.getRelyingPartyId(), e);
        }
    }

    /** Represents the internal state of a Shibboleth SSO Request while it's being processed by the IdP. */
    protected class ShibbolethSSORequestContext extends
            SAML1ProfileRequestContext<SAMLObject, Response, ShibbolethSSOConfiguration> {

        /** Current login context. */
        private ShibbolethSSOLoginContext loginContext;

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public ShibbolethSSORequestContext(ProfileRequest<ServletRequest> request,
                ProfileResponse<ServletResponse> response) {
            super(request, response);
        }

        /**
         * Gets the current login context.
         * 
         * @return current login context
         */
        public ShibbolethSSOLoginContext getLoginContext() {
            return loginContext;
        }

        /**
         * Sets the current login context.
         * 
         * @param context current login context
         */
        public void setLoginContext(ShibbolethSSOLoginContext context) {
            loginContext = context;
        }
    }
}