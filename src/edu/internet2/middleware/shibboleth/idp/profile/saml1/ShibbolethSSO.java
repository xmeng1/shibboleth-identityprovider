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

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.ShibbolethSSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;


import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.Audience;
import org.opensaml.saml1.core.AudienceRestrictionCondition;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.StatusMessage;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.signature.SignableXMLObject;

/**
 * Shibboleth, version 1.X, single sign-on profile handler.
 *
 * This profile implements the SSO profile from "Shibboleth Architecture Protocols and Profiles" - 10 September 2005.
 */
public class ShibbolethSSO extends AbstractSAML1ProfileHandler {
    
    
    /**
     * Request context for a ShibbolethSSO request.
     */
    protected class ShibbolethSSORequestContext {
        
        /** The servlet request. */
        protected HttpServletRequest servletRequest;
        
        /** The servlet response. */
        protected HttpServletResponse servletResponse;
        
        /** The profile request. */
        protected ProfileRequest<ServletRequest> profileRequest;
        
        /** The profile response. */
        protected ProfileResponse<ServletResponse> profileResponse;
        
        /** The AssertionConsumerService ("shire") URL. */
        protected String shire;
        
        /** The location to which the response should be sent ("target"). */
        protected String target;
        
        /** The SP's providerId in the metadata. */
        protected String providerId;
        
        /** The requestor's address. */
        protected String remoteAddr;
        
        /** The Shibboleth {@link LoginContext}. */
        protected LoginContext loginContex;
        
        /** The RelyingPartyConfiguration for the request. */
        protected RelyingPartyConfiguration rpConfiguration;
        
        /** The ShibbolethSSOConfiguration. */
        protected ShibbolethSSOConfiguration shibSSOConfiguration;
        
        /** The SPSSODescriptor. */
        protected SPSSODescriptor spDescriptor;
        
        /** The AssertionConsumerService to which the assertion should be sent. */
        protected AssertionConsumerService assertionConsumerService;
        
        /** The Assertion we generate in response. */
        protected Assertion assertion;
        
        public ShibbolethSSORequestContext() {
        }
        
        public ShibbolethSSORequestContext(final ProfileRequest<ServletRequest> profileRequest,
                final ProfileResponse<ServletResponse> profileResponse, String shire, String target,
                String providerId, String remoteAddr) {
            
            this.profileRequest = profileRequest;
            this.profileResponse = profileResponse;
            this.servletRequest = (HttpServletRequest) profileRequest.getRawRequest();
            this.servletResponse = (HttpServletResponse) profileResponse.getRawResponse();
            this.shire = shire;
            this.target = target;
            this.providerId = providerId;
            this.remoteAddr = remoteAddr;
        }

        public ProfileRequest<ServletRequest> getProfileRequest() {
            return profileRequest;
        }

        public void setProfileRequest(ProfileRequest<ServletRequest> profileRequest) {
            this.profileRequest = profileRequest;
            this.servletRequest = (HttpServletRequest) profileRequest.getRawRequest();
        }

        public ProfileResponse<ServletResponse> getProfileResponse() {
            return profileResponse;
        }

        public void setProfileResponse(ProfileResponse<ServletResponse> profileResponse) {
            this.profileResponse = profileResponse;
            this.servletResponse = (HttpServletResponse) profileResponse.getRawResponse();
        }
        
        public HttpServletRequest getServletRequest() {
            return servletRequest;
        }
        
        public void setServletRequest(HttpServletRequest servletRequest) {
            this.servletRequest = servletRequest;
        }
        
        public HttpServletResponse getServletResponse() {
            return servletResponse;
        }
        
        public void setServletResponse(HttpServletResponse servletResponse) {
            this.servletResponse = servletResponse;
        }
        
        public String getShire() {
            return shire;
        }
        
        public void setShire(String shire) {
            this.shire = shire;
        }
        
        public String getTarget() {
            return target;
        }
        
        public void setTarget(String target) {
            this.target = target;
        }
        
        public String getProviderId() {
            return providerId;
        }
        
        public void setProviderId(String providerId) {
            this.providerId = providerId;
        }
        
        public String getRemoteAddr() {
            return remoteAddr;
        }
        
        public void setRemoteAddr(String remoteAddr) {
            this.remoteAddr = remoteAddr;
        }
        
        public LoginContext getLoginContex() {
            return loginContex;
        }
        
        public void setLoginContex(LoginContext loginContext) {
            
            this.loginContex = loginContext;
            
            if (loginContext.getProfileHandlerURL() == null) {
                loginContext.setProfileHandlerURL(getServletRequest().getRequestURI());
            }
            
            getHttpSession().setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);
        }
        
        public RelyingPartyConfiguration getRpConfiguration() {
            return rpConfiguration;
        }
        
        public void setRpConfiguration(RelyingPartyConfiguration rpConfiguration) {
            this.rpConfiguration = rpConfiguration;
        }
        
        public Assertion getAssertion() {
            return assertion;
        }
        
        public void setAssertion(Assertion assertion) {
            this.assertion = assertion;
        }
        
        public ShibbolethSSOConfiguration getShibSSOConfiguration() {
            return shibSSOConfiguration;
        }
        
        public void setShibSSOConfiguration(ShibbolethSSOConfiguration shibSSOConfiguration) {
            this.shibSSOConfiguration = shibSSOConfiguration;
        }
        
        public SPSSODescriptor getSpDescriptor() {
            return spDescriptor;
        }
        
        public void setSpDescriptor(SPSSODescriptor spDescriptor) {
            this.spDescriptor = spDescriptor;
        }
        
        public AssertionConsumerService getAssertionConsumerService() {
            return assertionConsumerService;
        }
        
        public void setAssertionConsumerService(AssertionConsumerService assertionConsumers) {
            this.assertionConsumerService = assertionConsumers;
        }
        
        
        public HttpSession getHttpSession() {
            
            if (getServletRequest() != null) {
                return getServletRequest().getSession();
            } else {
                return null;
            }
        }
        
        public boolean equals(final Object obj) {
            
            if (obj == null) {
                return false;
            }
            
            if (getClass() != obj.getClass()) {
                return false;
            }
            
            final ShibbolethSSORequestContext other = (ShibbolethSSORequestContext) obj;
            
            if (servletRequest != other.servletRequest && (servletRequest == null || !this.servletRequest.equals(other.servletRequest))) {
                return false;
            }
            
            if (servletResponse != other.servletResponse && (servletResponse == null || !this.servletResponse.equals(other.servletResponse))) {
                return false;
            }
            
            if (shire != other.shire && (shire == null || !shire.equals(other.shire))) {
                return false;
            }
            
            if (target != other.target && (target == null || !target.equals(other.target))) {
                return false;
            }
            
            if (providerId != other.providerId && (providerId == null || !providerId.equals(other.providerId))) {
                return false;
            }
            
            if (remoteAddr != other.remoteAddr && (remoteAddr == null || !remoteAddr.equals(other.remoteAddr))) {
                return false;
            }
            
            return true;
        }
        
        public int hashCode() {
            
            int hash = 7;
            hash = 71 * hash + shire != null ? shire.hashCode() : 0;
            hash = 71 * hash + target != null ? target.hashCode() : 0;
            hash = 71 * hash + providerId != null ? providerId.hashCode() : 0;
            hash = 71 * hash + remoteAddr != null ? remoteAddr.hashCode() : 0;
            
            return hash;
        }
    }
    
    /**
     * Internal exception class used by utilty methods.
     */
    protected class ShibbolethSSOException extends Exception {
        
        public ShibbolethSSOException() {
        }
        
        public ShibbolethSSOException(final String message) {
            super(message);
        }
        
        public ShibbolethSSOException(final Throwable cause) {
            super(cause);
        }
        
        public ShibbolethSSOException(final String message, final Throwable cause) {
            super(message, cause);
        }
        
    }
    
    
    /** log4j. */
    private static final Logger log = Logger.getLogger(ShibbolethSSO.class);
    
    /** SAML 1 bearer confirmation method URI. */
    protected static final String BEARER_CONF_METHOD_URI = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
    
    /** SAML 1 artifact confirmation method URI */
    protected static final String ARTIFACT_CONF_METHOD_URI = "urn:oasis:names:tc:SAML:1.0:cm:artifact";
    
    /** SAML 1.1 SPSSO protocol URI */
    protected static final String SAML11_PROTOCOL_URI = "urn:oasis:names:tc:SAML:1.1:protocol";
    
    /** SAML 1 Browser/POST protocol URI. */
    protected static final String PROFILE_BROWSER_POST_URI = "urn:oasis:names:tc:SAML:1.0:profiles:browser-post";
    
    /** SAML 1 Artifact protocol URI. */
    protected static final String PROFILE_ARTIFACT_URI = "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01";
    
    /** The digest algorithm for generating SP cookies. */
    protected static final String RP_COOKIE_DIGEST_ALG = "SHA-1";
    
    /** Profile ID for this handler. */
    protected static final String PROFILE_ID = "urn:mace:shibboleth:1.0:profiles:AuthnRequest";
    
    /** The request parameter containing the time the request was made. */
    protected static final String REQUEST_PARAMETER_TIME = "time";
    
    /** HttpSession key for the ShibbolethSSORequestContext. */
    protected static final String REQUEST_CONTEXT_SESSION_KEY = "edu.internet2.middleware.shibboleth.idp.profile.ShibbolethSSORequestContext";
    
    /** The path to the IdP's AuthenticationManager servlet */
    protected String authnMgrURL;
    
    /** The URI of the default authentication method */
    protected String authenticationMethodURI;
    
    /** Builder for AuthenticationStatement objects. */
    protected SAMLObjectBuilder<AuthenticationStatement> authnStmtBuilder;
    
    /** Builder for Subject elements. */
    protected SAMLObjectBuilder<Subject> subjectBuilder;
    
    /** Builder for SubjectConfirmation objects. */
    protected SAMLObjectBuilder<SubjectConfirmation> subjConfBuilder;
    
    /** Builder for SubjectConfirmationMethod objects. */
    protected SAMLObjectBuilder<ConfirmationMethod> confMethodBuilder;
    
    /** Builder for NameIdentifiers. */
    protected SAMLObjectBuilder<NameIdentifier> nameIdentifierBuilder;
    
    /** Builder for Audience elements. */
    protected SAMLObjectBuilder<Audience> audienceBuilder;
    
    /** Builder for AudienceRestrictionCondition elements. */
    protected SAMLObjectBuilder<AudienceRestrictionCondition> audienceRestrictionBuilder;
    
    /** Builder for Assertions. */
    protected SAMLObjectBuilder<Assertion> assertionBuilder;
    
    /** Builder for Response objects. */
    protected SAMLObjectBuilder<Response> responseBuilder;
    
    /** Block stale requests. */
    protected boolean blockStaleRequests = false;
    
    /**
     * Time after which an authn request is considered stale (in seconds). Defaults to 30 minutes.
     */
    protected int requestTTL = 1800;
    
    /** Protocol binding to use for the Authentication Assertion. */
    protected static enum PROTOCOL_BINDING {
        BROWSER_POST, ARTIFACT
    };
    
    /**
     * Default constructor.
     */
    public ShibbolethSSO() {
        
        // setup SAML object builders
        
        assertionBuilder           = (SAMLObjectBuilder<Assertion>) getBuilderFactory().getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        authnStmtBuilder           = (SAMLObjectBuilder<AuthenticationStatement>) getBuilderFactory().getBuilder(AuthenticationStatement.DEFAULT_ELEMENT_NAME);
        subjectBuilder             = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        subjConfBuilder            = (SAMLObjectBuilder<SubjectConfirmation>) getBuilderFactory().getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        confMethodBuilder          = (SAMLObjectBuilder<ConfirmationMethod>) getBuilderFactory().getBuilder(ConfirmationMethod.DEFAULT_ELEMENT_NAME);
        nameIdentifierBuilder      = (SAMLObjectBuilder<NameIdentifier>) getBuilderFactory().getBuilder(NameIdentifier.DEFAULT_ELEMENT_NAME);
        audienceBuilder            = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestrictionCondition>) getBuilderFactory().getBuilder(AudienceRestrictionCondition.DEFAULT_ELEMENT_NAME);
        responseBuilder            = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        
    }
    
    /** {@inheritDoc} */
    public String getProfileId() {
        return PROFILE_ID;
    }
    
    /**
     * Set the authentication manager.
     *
     * @param authnManagerURL The URL of the IdP's AuthenticationManager servlet
     */
    public void setAuthenticationManager(String authnManagerURL) {
        authnMgrURL = authnManagerURL;
    }
    
    /**
     * Set the authentication method URI.
     *
     * The URI SHOULD come from oasis-sstc-saml-core-1.1, section 7.1
     *
     * @param authMethod The authentication method's URI
     */
    public void setAuthenticationMethodURI(String authMethod) {
        authenticationMethodURI = authMethod;
    }
    
    /**
     * Set if old requests should be blocked.
     *
     * @param blockStaleRequests boolean flag.
     */
    public void setBlockStaleRequests(boolean blockStaleRequests) {
        this.blockStaleRequests = blockStaleRequests;
    }
    
    /**
     * Return if stale requests are blocked.
     *
     * @return <code>true</code> if old requests are blocked.
     */
    public boolean getBlockStaleRequests() {
        return blockStaleRequests;
    }
    
    /**
     * Set request TTL.
     *
     * @param ttl Request timeout (in seconds).
     */
    public void setRequestTTL(int ttl) {
        requestTTL = ttl;
    }
    
    /**
     * Get Request TTL. This is the time after which a request is considered stale.
     *
     * @return request timeout (in seconds).
     */
    public int getRequestTTL() {
        return requestTTL;
    }
    
    /** {@inheritDoc} */
    public void processRequest(final ProfileRequest<ServletRequest> request, final ProfileResponse<ServletResponse> response) throws ProfileException {
        
        // Only http servlets are supported for now.
        if (!(request.getRawRequest() instanceof HttpServletRequest)) {
            log.error("Received a non-HTTP request.");
            throw new ProfileException("Received a non-HTTP request.");
        }
        
        // This method is called twice.
        // On the first time, there will be no ShibbolethSSORequestContext object. We redirect control to the
        // AuthenticationManager to authenticate the user. The AuthenticationManager then redirects control
        // back to this servlet. On the "return leg" connection, there will be a ShibbolethSSORequestContext object.
        
        HttpServletRequest req = (HttpServletRequest) request.getRawRequest();
        Object o = req.getSession().getAttribute(REQUEST_CONTEXT_SESSION_KEY);
        if (o != null && !(o instanceof ShibbolethSSORequestContext)) {
            log.error("SAML 1 Authentication Request Handler: Invalid session data found for ShibbolethSSORequestContext");
            throw new ProfileException("SAML 1 Authentication Request Handler: Invalid session data found for ShibbolethSSORequestContext");
        }
        
        if (o == null) {
            setupNewRequest(request, response);
        } else {
            ShibbolethSSORequestContext requestContext = (ShibbolethSSORequestContext)o;
            finishProcessingRequest(requestContext);
        }
    }
    
    /**
     * Begin processing a SAML 1.x authentication request.
     * This ensurues that the request is well-formed and that
     * appropriate metadata can be found for the SP.
     * Once these conditions are met, control is passed to
     * the AuthenticationManager to authenticate the user.
     *
     * @param request The ProfileRequest.
     * @param response The ProfileResponse.
     *
     * @throws ProfileException On error.
     */
    protected void setupNewRequest(final ProfileRequest<ServletRequest> request, final ProfileResponse<ServletResponse> response) throws ProfileException {
        
        try {
            ShibbolethSSORequestContext requestContext = new ShibbolethSSORequestContext();
            requestContext.setProfileRequest(request);
            requestContext.setProfileResponse(response);
                    
            // extract the (mandatory) request parameters.
            getRequestParameters(requestContext);
            
            // check for stale requests
            if (blockStaleRequests) {
                String cookieName = getRPCookieName(requestContext.getProviderId());
                if (!validateFreshness(requestContext, cookieName)) {
                    log.error("SAML 1 Authentication Request Handler: detected stale authentiation request");
                    throw new ProfileException("SAML 1 Authentication Request Handler: detected stale authentiation request");
                }
                
                writeFreshnessCookie(requestContext, cookieName);
            }
            
            // check if the user has already been authenticated
            Object o = requestContext.getHttpSession().getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
            if (o == null) {
                
                // the user hasn't been authenticated, so forward the request
                // to the AuthenticationManager. When the AuthenticationManager
                // is done it will forward the request back to this servlet.
                
                // don't force reauth or passive auth
                requestContext.setLoginContex(new LoginContext(false, false));
                
                try {
                    RequestDispatcher dispatcher = requestContext.getServletRequest().getRequestDispatcher(authnMgrURL);
                    dispatcher.forward(requestContext.getServletRequest(), requestContext.getServletResponse());
                } catch (IOException ex) {
                    log.error("Error forwarding SAML 1 SSO request to AuthenticationManager", ex);
                    throw new ProfileException("Error forwarding SAML 1 SSO request to AuthenticationManager", ex);
                } catch (ServletException ex) {
                    log.error("Error forwarding SAML 1 SSO request to AuthenticationManager", ex);
                    throw new ProfileException("Error forwarding SAML 1 SSO request to AuthenticationManager", ex);
                }
            }
            
        } catch (ShibbolethSSOException ex) {
            log.error("Error processing Shibboleth SSO request", ex);
            throw new ProfileException("Error processing Shibboleth SSO request", ex);
        }
    }
    
    
    /**
     * Process the "return leg" of a SAML 1 authentication request.
     *
     * This evaluates the AuthenticationManager's LoginContext, and generates an Authentication Assertion, as appropriate.
     *
     * @param requestContext The context for the request.
     *
     * @throws ProfileException On error.
     */
    protected void finishProcessingRequest(final ShibbolethSSORequestContext requestContext) throws ProfileException {
        
        try {
            
            LoginContext loginCtx = requestContext.getLoginContex();
            
            if (!loginCtx.getAuthenticationOK()) {
                throw new ShibbolethSSOException("Authentication failed: " + loginCtx.getAuthenticationFailureMessage());
            }
            
            // The user successfully authenticated,
            // so build the appropriate AuthenticationStatement.
            
            DateTime now = new DateTime();
            
            generateAuthenticationAssertion(requestContext, now);
            encodeSAMLResponse(requestContext);
            
        } catch (ShibbolethSSOException ex) {
            log.error("Error processing Shibboleth SSO request", ex);
            throw new ProfileException("Error processing Shibboleth SSO request", ex);
        }
    }
    
    /**
     * Encode the SAML response.
     *
     * @param requestContext The context for the request.
     *
     * @throws ProfileException On error.
     */
    protected void encodeSAMLResponse(final ShibbolethSSORequestContext requestContext) throws ProfileException {
        
        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setID(getIdGenerator().generateIdentifier());
        samlResponse.setIssueInstant(new DateTime());
        samlResponse.setVersion(SAML_VERSION);
        samlResponse.setRecipient(requestContext.getProviderId());
        
        Status status;
        
        if (requestContext.getLoginContex().getAuthenticationOK()) {
            status = buildStatus("Success", null);
            List<Assertion> assertionList = samlResponse.getAssertions();
            assertionList.add(requestContext.getAssertion());
        } else {
            status = buildStatus("Responder", null);
        }
        
        samlResponse.setStatus(status);
        
        encodeResponse(PROFILE_ID, requestContext.getProfileResponse(), samlResponse,
                requestContext.getRpConfiguration(), requestContext.getSpDescriptor(),
                (Endpoint) requestContext.getAssertionConsumerService());
    }
    
    /**
     * Get the Shibboleth profile-specific request parameters.
     *
     * @param request The servlet request from the SP.
     * @param response The servlet response.
     *
     * @throw ShibbolethSSOException On Error.
     */
    protected void getRequestParameters(final ShibbolethSSORequestContext requestContext) throws ShibbolethSSOException {
        
        HttpServletRequest servletRequest = requestContext.getServletRequest();
        
        String target = servletRequest.getParameter("target");
        String providerId = servletRequest.getParameter("providerId");
        String shire = servletRequest.getParameter("shire");
        String remoteAddr = servletRequest.getRemoteAddr();
        
        if (target == null || target.equals("")) {
            log.error("Shib 1 SSO request is missing or contains an invalid target parameter");
            throw new ShibbolethSSOException("Shib 1 SSO request is missing or contains an invalid target parameter");
        }
        
        if (providerId == null || providerId.equals("")) {
            log.error("Shib 1 SSO request is missing or contains an invalid provierId parameter");
            throw new ShibbolethSSOException("Shib 1 SSO request is missing or contains an invalid provierId parameter");
        }
        
        if (shire == null || providerId.equals("")) {
            log.error("Shib 1 SSO request is missing or contains an invalid shire parameter");
            throw new ShibbolethSSOException("Shib 1 SSO request is missing or contains an invalid shire parameter");
        }
        
        if (remoteAddr == null || remoteAddr.equals("")) {
            log.error("Unable to obtain requestor address when processing Shib 1 SSO request");
            throw new ShibbolethSSOException("Unable to obtain requestor address when processing Shib 1 SSO request");
        }
        
        requestContext.setTarget(target);
        requestContext.setProviderId(providerId);
        requestContext.setShire(shire);
        requestContext.setRemoteAddr(remoteAddr);
    }
    
    /**
     * Generate a SAML 1 AuthenticationStatement.
     *
     * @param requestContext The context for the ShibbolethSSO request.
     * @param now The current timestamp
     *
     * @return A SAML 1 Authentication Assertion or <code>null</code> on error.
     */
    protected Assertion generateAuthenticationAssertion(final ShibbolethSSORequestContext requestContext,
             final DateTime now) {
        
        String providerId = requestContext.getRpConfiguration().getProviderId();
        
        Assertion authenticationAssertion = assertionBuilder.buildObject();
        authenticationAssertion.setIssueInstant(now);
        authenticationAssertion.setVersion(SAML_VERSION);
        authenticationAssertion.setIssuer(providerId);
        authenticationAssertion.setID(getIdGenerator().generateIdentifier());
        
        Conditions conditions = authenticationAssertion.getConditions();
        conditions.setNotBefore(now.minusSeconds(30)); // for now, clock skew is hard-coded to 30 seconds.
        conditions.setNotOnOrAfter(now.plusMillis((int)requestContext.getShibSSOConfiguration().getAssertionLifetime()));
        
        List<AudienceRestrictionCondition> audienceRestrictions = conditions.getAudienceRestrictionConditions();
        AudienceRestrictionCondition restrictionCondition = audienceRestrictionBuilder.buildObject();
        audienceRestrictions.add(restrictionCondition);
        
        // add the RelyingParty to the audience.
        Audience rpAudience = audienceBuilder.buildObject();
        rpAudience.setUri(requestContext.getRpConfiguration().getProviderId());
        restrictionCondition.getAudiences().add(rpAudience);
        
        // if necessary, explicitely add the SP to the audience.
        if (!providerId.equals(requestContext.getProviderId())) {
            Audience spAudience = (Audience) audienceBuilder.buildObject();
            spAudience.setUri(requestContext.getProviderId());
            restrictionCondition.getAudiences().add(spAudience);
        }
        
        AuthenticationStatement authenticationStatement = authnStmtBuilder.buildObject();
        authenticationStatement.setSubject(buildSubject(requestContext));
        authenticationStatement.setAuthenticationInstant(requestContext.getLoginContex().getAuthenticationInstant());
        authenticationStatement.setAuthenticationMethod(authenticationMethodURI);
        
        authenticationAssertion.getAuthenticationStatements().add(authenticationStatement);
        
        if (requestContext.getSpDescriptor().getWantAssertionsSigned()) {
            signAssertion(authenticationAssertion, requestContext.getRpConfiguration(), requestContext.getShibSSOConfiguration());
        }
        
        return authenticationAssertion;
    }
    
    
    /**
     * Ensure that metadata can be found for the authentication request.
     * If found, the request context is updated to reflect the appropriate entries.
     *
     * @param requestContext The context for the current request.
     *
     * @throws ShibbolethSSOException On error.
     */
    protected void validateRequestAgainstMetadata(final ShibbolethSSORequestContext requestContext) throws ShibbolethSSOException {
        
        RelyingPartyConfiguration relyingParty = getRelyingPartyConfigurationManager().getRelyingPartyConfiguration(requestContext.getProviderId());
        ProfileConfiguration temp = relyingParty.getProfileConfigurations().get(ShibbolethSSOConfiguration.PROFILE_ID);
        if (temp == null) {
            log.error("No profile configuration registered for " + ShibbolethSSOConfiguration.PROFILE_ID);
            throw new ShibbolethSSOException("No profile configuration registered for " + ShibbolethSSOConfiguration.PROFILE_ID);
        }
        
        ShibbolethSSOConfiguration ssoConfig = (ShibbolethSSOConfiguration) temp;
        SPSSODescriptor spDescriptor;
        
        try {
            spDescriptor = getMetadataProvider().getEntityDescriptor(relyingParty.getRelyingPartyId()).getSPSSODescriptor(SAML11_PROTOCOL_URI);
        } catch (MetadataProviderException ex) {
            log.error("Unable to locate metadata for SP " + requestContext.getProviderId() + " for protocol " + SAML11_PROTOCOL_URI, ex);
            throw new ShibbolethSSOException("Unable to locate metadata for SP " + requestContext.getProviderId() + " for protocol " + SAML11_PROTOCOL_URI, ex);
        }
        
        if (spDescriptor == null) {
            log.error("Unable to locate metadata for SP " + requestContext.getProviderId() + " for protocol " + SAML11_PROTOCOL_URI);
            throw new ShibbolethSSOException("Unable to locate metadata for SP " + requestContext.getProviderId() + " for protocol " + SAML11_PROTOCOL_URI);
        }
        
        
        // validate the AssertionConsumer ("shire") URL against the AssertionConsumerService endpoints in the metadata.
        if (!(evaluateACSEndpoint(requestContext, requestContext.getSpDescriptor().getDefaultAssertionConsumerService()))) {
            
            // if the default AssertionConsumerService endpoint was not valid, iterate over all remaining endpoints.
            boolean found = false;
            for (AssertionConsumerService candidateEndpoint : requestContext.getSpDescriptor().getAssertionConsumerServices()) {
                if (evaluateACSEndpoint(requestContext, candidateEndpoint)) {
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                log.error("SAML 1 AuthenticationRequest Handler: Unable to find AssertionConsumerService " +
                        requestContext.getShire() + " for SP " + requestContext.getProviderId() + 
                        " for protocol " + SAML11_PROTOCOL_URI);
                throw new ShibbolethSSOException("SAML 1 AuthenticationRequest Handler: Unable to find AssertionConsumerService " +
                        requestContext.getShire() + " for SP " + requestContext.getProviderId() + 
                        " for protocol " + SAML11_PROTOCOL_URI);
            }
        }
        
        
        // spDescriptor returns a reference to an internal mutable copy, so make a copy of it.
        List<AssertionConsumerService> consumerURLs =
                new ArrayList<AssertionConsumerService>(requestContext.getSpDescriptor().getAssertionConsumerServices().size());
        
        // filter out any list elements that don't have the correct location field.
        // copy any consumerURLs with the correct location
        for (AssertionConsumerService service : requestContext.getSpDescriptor().getAssertionConsumerServices()) {
            if (service.getLocation().equals(requestContext.getShire())) {
                consumerURLs.add(service);
            }
        }
        if (consumerURLs.size() == 0) {
            log.error("Unable to validate AssertionConsumerService URL against metadata: " + requestContext.getShire()
                    + " not found for SP " + requestContext.getProviderId() + " for protocol " + SAML11_PROTOCOL_URI);
            throw new ShibbolethSSOException("Unable to validate AssertionConsumerService URL against metadata: " + requestContext.getShire()
                    + " not found for SP " + requestContext.getProviderId() + " for protocol " + SAML11_PROTOCOL_URI);
        }
        
        requestContext.setRpConfiguration(relyingParty);
        requestContext.setShibSSOConfiguration(ssoConfig);
        requestContext.setSpDescriptor(spDescriptor);
    }
    
    
    /**
     * Evaluate a specific AssertionConsumerService endpoint against the request's "shire" parameter.
     * If it matches, update the request context to use this endpoint.
     *
     * @param requestContext The context for the current request.
     * @param candidateEndpoint An endpoint to consider for use for the response.
     *
     * @return <code>true</code> if <code>candidateEndpoint</code> is valid; otherwise, <code>false</code>.
     */
    protected boolean evaluateACSEndpoint(final ShibbolethSSORequestContext requestContext, final AssertionConsumerService candidateEndpoint) {
        
        if (requestContext.getShire().equals(candidateEndpoint.getLocation())) {
            requestContext.setAssertionConsumerService(candidateEndpoint);
            return true;
        } else {
            return false;
        }
    }
    
    
    
    /**
     * Validate the "freshness" of an authn request. If the reqeust is more than 30 minutes old, reject it.
     *
     * @param requestContext The context for the current request.
     * @param cookieName The name of the RP's cookie.
     *
     * @return <code>true</code> if the cookie is fresh; otherwise <code>false</code>
     *
     */
    protected boolean validateFreshness(final ShibbolethSSORequestContext requestContext, String cookieName) {
        
        if (cookieName == null) {
            return false;
        }
        
        String timestamp = requestContext.getServletRequest().getParameter(REQUEST_PARAMETER_TIME);
        if (timestamp == null || timestamp.equals("")) {
            return true;
        }
        
        long reqtime;
        try {
            reqtime = Long.parseLong(timestamp);
        } catch (NumberFormatException ex) {
            log.error("Unable to parse Authentication Request's timestamp", ex);
            return false;
        }
        
        if (reqtime * 1000 < (System.currentTimeMillis() - requestTTL * 1000)) {
            return false;
        }
        
        for (Cookie cookie : requestContext.getServletRequest().getCookies()) {
            if (cookieName.equals(cookie.getName())) {
                try {
                    long cookieTime = Long.parseLong(cookie.getValue());
                    if (reqtime <= cookieTime) {
                        return false;
                    }
                } catch (NumberFormatException ex) {
                    log.error("Unable to parse freshness cookie's timestamp", ex);
                    return false;
                }
            }
        }
        
        return true;
    }
    
    /**
     * Generate the RP's cookie name
     *
     * @param providerID The RP's providerID
     *
     * @throws ProfileException If unable to find a JCE provider for SHA-1
     *
     * @return the RP's cookie name
     */
    protected String getRPCookieName(String providerID) throws ProfileException {
        
        try {
            MessageDigest digester = MessageDigest.getInstance(RP_COOKIE_DIGEST_ALG);
            return "shib_sp_" + new String(Hex.encode(digester.digest(providerID.getBytes("UTF-8"))));
        } catch (NoSuchAlgorithmException ex) {
            throw new ProfileException("Unabel to create RPCookie", ex);
        } catch (UnsupportedEncodingException ex) {
            // this should never happen. UTF-8 encoding should always be supported.
            throw new ProfileException("Unable to locate UTF-8 encoder", ex);
        }
    }
    
    /**
     * Write the current time into the freshness cookie.
     *
     * @param requestContext The context for the current request.
     * @param cookieName The name of the cookie to write.
     */
    protected void writeFreshnessCookie(final ShibbolethSSORequestContext requestContext, String cookieName) {
        
        String timestamp = requestContext.getServletRequest().getParameter("time");
        if (timestamp == null || timestamp.equals("")) {
            return;
        }
        
        Cookie cookie = new Cookie(cookieName, timestamp);
        cookie.setSecure(true);
        requestContext.getServletResponse().addCookie(cookie);
    }
    
    /**
     * Generate a SAML 1 Subject element.
     *
     * @param requestContext The context for the current request.
     *
     * @return a Subject object.
     */
    protected Subject buildSubject(final ShibbolethSSORequestContext requestContext) {
        
        LoginContext loginContext = requestContext.getLoginContex();
        ShibbolethSSOConfiguration ssoConfig =  requestContext.getShibSSOConfiguration();    
        
        String protocolBinding = requestContext.getAssertionConsumerService().getBinding();
        String confirmationMethod = null;
        
        // Set the SubjectConfirmationMethod appropriately depending on the protocol binding
        if (protocolBinding.equals(PROFILE_ARTIFACT_URI)) {
            confirmationMethod = ARTIFACT_CONF_METHOD_URI;
        } else if (protocolBinding.equals(PROFILE_BROWSER_POST_URI)) {
            confirmationMethod = BEARER_CONF_METHOD_URI;
        }
        
        Subject subject = subjectBuilder.buildObject();
        
        NameIdentifier nameID = nameIdentifierBuilder.buildObject();
        nameID.setFormat(ssoConfig.getDefaultNameIDFormat());
        
        String username = loginContext.getUserID();
        
        // XXX: todo: map the username onto an appropriate format
        nameID.setNameQualifier(username);
        
        if (confirmationMethod != null) {
            
            ConfirmationMethod m = confMethodBuilder.buildObject();
            m.setConfirmationMethod(confirmationMethod);
            
            SubjectConfirmation subjConf = subjConfBuilder.buildObject();
            subjConf.getConfirmationMethods().add(m);
            subject.setSubjectConfirmation(subjConf);
        }
        
        return subject;
    }
}