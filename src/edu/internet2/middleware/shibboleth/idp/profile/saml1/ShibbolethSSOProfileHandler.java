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
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.encoding.MessageEncoder;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.ShibbolethConstants;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.ShibbolethSSOConfiguration;
import edu.internet2.middleware.shibboleth.common.util.HttpHelper;
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

    /**
     * Constructor.
     * 
     * @param authnManagerPath path to the authentication manager servlet
     * 
     * @throws IllegalArgumentException thrown if either the authentication manager path or encoding binding URI are
     *             null or empty
     */
    public ShibbolethSSOProfileHandler(String authnManagerPath) {
        if (DatatypeHelper.isEmpty(authnManagerPath)) {
            throw new IllegalArgumentException("Authentication manager path may not be null");
        }

        authenticationManagerPath = authnManagerPath;

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

        if (response.getRawResponse().isCommitted()) {
            log.error("HTTP Response already committed");
        }

        if (log.isDebugEnabled()) {
            log.debug("Processing incomming request");
        }
        HttpSession httpSession = ((HttpServletRequest) request.getRawRequest()).getSession(true);
        if (httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY) == null) {
            if (log.isDebugEnabled()) {
                log.debug("User session does not contain a login context, processing as first leg of request");
            }
            performAuthentication(request, response);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("User session contains a login context, processing as second leg of request");
            }
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
        if (getRelyingPartyConfiguration(loginContext.getRelyingPartyId()) == null) {
            log.error("Shibboleth SSO profile is not configured for relying party " + loginContext.getRelyingPartyId());
            throw new ProfileException("Shibboleth SSO profile is not configured for relying party "
                    + loginContext.getRelyingPartyId());
        }

        httpSession.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);

        try {
            RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(authenticationManagerPath);
            dispatcher.forward(httpRequest, httpResponse);
            return;
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

            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(providerId);
            if (rpConfig == null) {
                log.error("No relying party configuration available for " + providerId);
                throw new ProfileException("No relying party configuration available for " + providerId);
            }
            loginContext.getRequestedAuthenticationMethods().add(rpConfig.getDefaultAuthenticationMethod());

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
        loginContext.setProfileHandlerURL(HttpHelper.getRequestUriWithoutContext(request));
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
     * 
     * @throws ProfileException thrown if asserting and relying party metadata can not be located
     */
    protected ShibbolethSSORequestContext buildRequestContext(ShibbolethSSOLoginContext loginContext,
            ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response) throws ProfileException {
        ShibbolethSSORequestContext requestContext = new ShibbolethSSORequestContext(request, response);

        requestContext.setLoginContext(loginContext);

        requestContext.setPrincipalName(loginContext.getPrincipalName());

        requestContext.setPrincipalAuthenticationMethod(loginContext.getAuthenticationMethod());

        String relyingPartyId = loginContext.getRelyingPartyId();

        requestContext.setRelyingPartyId(relyingPartyId);

        populateRelyingPartyData(requestContext);
        
        populateAssertingPartyData(requestContext);
        
        return requestContext;
    }

    /**
     * Populates the relying party entity and role metadata and relying party configuration data.
     * 
     * @param requestContext current request context with relying party ID populated
     * 
     * @throws ProfileException thrown if metadata can not be located for the relying party
     */
    protected void populateRelyingPartyData(ShibbolethSSORequestContext requestContext) throws ProfileException {
        try {
            requestContext.setRelyingPartyMetadata(getMetadataProvider().getEntityDescriptor(
                    requestContext.getRelyingPartyId()));

            RoleDescriptor relyingPartyRole = requestContext.getRelyingPartyMetadata().getSPSSODescriptor(
                    ShibbolethConstants.SAML11P_NS);

            if (relyingPartyRole == null) {
                relyingPartyRole = requestContext.getRelyingPartyMetadata()
                        .getSPSSODescriptor(ShibbolethConstants.SAML10P_NS);
                if (relyingPartyRole == null) {
                    throw new MetadataProviderException("Unable to locate SPSSO role descriptor for entity "
                            + requestContext.getRelyingPartyId());
                }
            }
            requestContext.setRelyingPartyRoleMetadata(relyingPartyRole);

            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(requestContext.getRelyingPartyId());
            requestContext.setRelyingPartyConfiguration(rpConfig);

            requestContext.setProfileConfiguration((ShibbolethSSOConfiguration) rpConfig
                    .getProfileConfiguration(ShibbolethSSOConfiguration.PROFILE_ID));

        } catch (MetadataProviderException e) {
            log.error("Unable to locate metadata for relying party " + requestContext.getRelyingPartyId());
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                    "Unable to locate metadata for relying party " + requestContext.getRelyingPartyId()));
            throw new ProfileException("Unable to locate metadata for relying party "
                    + requestContext.getRelyingPartyId());
        }
    }

    /**
     * Populates the asserting party entity and role metadata.
     * 
     * @param requestContext current request context with relying party configuration populated
     * 
     * @throws ProfileException thrown if metadata can not be located for the asserting party
     */
    protected void populateAssertingPartyData(ShibbolethSSORequestContext requestContext) throws ProfileException {
        String assertingPartyId = requestContext.getRelyingPartyConfiguration().getProviderId();

        try {
            requestContext.setAssertingPartyId(assertingPartyId);

            requestContext.setAssertingPartyMetadata(getMetadataProvider().getEntityDescriptor(assertingPartyId));

            RoleDescriptor assertingPartyRole = requestContext.getAssertingPartyMetadata().getIDPSSODescriptor(
                    ShibbolethConstants.SHIB_SSO_PROFILE_URI);
            if (assertingPartyRole == null) {
                throw new MetadataProviderException("Unable to locate IDPSSO role descriptor for entity "
                        + assertingPartyId);
            }
            requestContext.setAssertingPartyRoleMetadata(assertingPartyRole);
        } catch (MetadataProviderException e) {
            log.error("Unable to locate metadata for asserting party " + assertingPartyId);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                    "Unable to locate metadata for relying party " + assertingPartyId));
            throw new ProfileException("Unable to locate metadata for relying party " + assertingPartyId);
        }
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

        BasicEndpointSelector endpointSelector = new BasicEndpointSelector();
        endpointSelector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        endpointSelector.setMetadataProvider(getMetadataProvider());
        endpointSelector.setRelyingParty(requestContext.getRelyingPartyMetadata());
        endpointSelector.setRelyingPartyRole(requestContext.getRelyingPartyRoleMetadata());
        endpointSelector.setSamlRequest(requestContext.getSamlRequest());
        endpointSelector.getSupportedIssuerBindings().addAll(getMessageEncoderFactory().getEncoderBuilders().keySet());
        Endpoint relyingPartyEndpoint = endpointSelector.selectEndpoint();

        if (relyingPartyEndpoint == null) {
            log.error("Unable to determine endpoint, from metadata, for relying party "
                    + requestContext.getRelyingPartyId() + " acting in SPSSO role");
            throw new ProfileException("Unable to determine endpoint, from metadata, for relying party "
                    + requestContext.getRelyingPartyId() + " acting in SPSSO role");
        }

        MessageEncoder<ServletResponse> encoder = getMessageEncoderFactory().getMessageEncoder(
                relyingPartyEndpoint.getBinding());

        super.populateMessageEncoder(encoder);
        ProfileResponse<ServletResponse> profileResponse = requestContext.getProfileResponse();
        encoder.setResponse(profileResponse.getRawResponse());
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
            SAML1ProfileRequestContext<Request, Response, ShibbolethSSOConfiguration> {

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