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

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.encoding.MessageEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.GetComplete;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AbstractSAML2ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;

/**
 * Abstract SAML 2.0 Authentication Request profile handler.
 */
public abstract class AbstractAuthenticationRequest extends AbstractSAML2ProfileHandler {
    
    
    /**
     * Represents the internal state of a SAML 2.0 Authentiation Request while it's being processed by the IdP.
     */
    protected class AuthenticationRequestContext {
        
        /** The ProfileRequest. */
        protected ProfileRequest<ServletRequest> profileRequest;
        
        /** The ProfileResponse. */
        protected ProfileResponse<ServletResponse> profileResponse;
        
        /** The HttpServletRequest. */
        protected HttpServletRequest servletRequest;
        
        /** The HttpServletResponse. */
        protected HttpServletResponse servletResponse;
        
        /** The SAML 2.0 AuthnRequest. */
        protected AuthnRequest authnRequest;
        
        /** The issuer. */
        protected String issuer;
        
        /** The Subject. */
        protected Subject subject;
        
        /** The Response. */
        protected Response response;
        
        /** The IdP's LoginContext. */
        protected LoginContext loginContext;
        
        /** The RelyingPartyConfiguration. */
        protected RelyingPartyConfiguration rpConfig;
        
        /** The SSOConfiguration. */
        protected SSOConfiguration ssoConfig;
        
        /** The SPSSOConfiguration. */
        protected SPSSODescriptor spDescriptor;
        
        /** The AssertionConsumerService endpoint. */
        protected AssertionConsumerService assertionConsumerService;
        
        public AuthenticationRequestContext() {
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
        
        public HttpSession getHttpSession() {
            
            if (getServletRequest() != null) {
                return getServletRequest().getSession();
            } else {
                return null;
            }
        }
        
        public AuthnRequest getAuthnRequest() {
            return authnRequest;
        }
        
        public void setAuthnRequest(AuthnRequest authnRequest) {
            this.authnRequest = authnRequest;
        }
        
        public String getIssuer() {
            return issuer;
        }
        
        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }
        
        public Subject getSubject() {
            return subject;
        }
        
        public void setSubject(Subject subject) {
            this.subject = subject;
        }
        
        public LoginContext getLoginContext() {
            return loginContext;
        }
        
        public void setLoginContext(LoginContext loginContext) {
            this.loginContext = loginContext;
        }
        
        public RelyingPartyConfiguration getRpConfig() {
            return rpConfig;
        }
        
        public void setRpConfig(RelyingPartyConfiguration rpConfig) {
            this.rpConfig = rpConfig;
        }
        
        public SSOConfiguration getSsoConfig() {
            return ssoConfig;
        }
        
        public void setSsoConfig(SSOConfiguration ssoConfig) {
            this.ssoConfig = ssoConfig;
        }
        
        public SPSSODescriptor getSpDescriptor() {
            return spDescriptor;
        }
        
        public void setSpDescriptor(SPSSODescriptor spDescriptor) {
            this.spDescriptor = spDescriptor;
        }
        
        public Response getResponse() {
            return response;
        }
        
        public void setResponse(Response response) {
            this.response = response;
        }
        
        public AssertionConsumerService getAssertionConsumerService() {
            return assertionConsumerService;
        }
        
        public void setAssertionConsumerService(AssertionConsumerService assertionConsumerService) {
            this.assertionConsumerService = assertionConsumerService;
        }
        
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            
            if (getClass() != obj.getClass()) {
                return false;
            }
            
            final edu.internet2.middleware.shibboleth.idp.profile.saml2.AbstractAuthenticationRequest.AuthenticationRequestContext other = (edu.internet2.middleware.shibboleth.idp.profile.saml2.AbstractAuthenticationRequest.AuthenticationRequestContext) obj;
            
            if (this.profileRequest != other.profileRequest && (this.profileRequest == null || !this.profileRequest.equals(other.profileRequest))) {
                return false;
            }
            
            if (this.profileResponse != other.profileResponse && (this.profileResponse == null || !this.profileResponse.equals(other.profileResponse))) {
                return false;
            }
            
            if (this.servletRequest != other.servletRequest && (this.servletRequest == null || !this.servletRequest.equals(other.servletRequest))) {
                return false;
            }
            
            if (this.servletResponse != other.servletResponse && (this.servletResponse == null || !this.servletResponse.equals(other.servletResponse))) {
                return false;
            }
            
            if (this.authnRequest != other.authnRequest && (this.authnRequest == null || !this.authnRequest.equals(other.authnRequest))) {
                return false;
            }
            
            if (this.issuer != other.issuer && (this.issuer == null || !this.issuer.equals(other.issuer))) {
                return false;
            }
            
            if (this.subject != other.subject && (this.subject == null || !this.subject.equals(other.subject))) {
                return false;
            }
            
            if (this.response != other.response && (this.response == null || !this.response.equals(other.response))) {
                return false;
            }
            
            if (this.loginContext != other.loginContext && (this.loginContext == null || !this.loginContext.equals(other.loginContext))) {
                return false;
            }
            
            if (this.rpConfig != other.rpConfig && (this.rpConfig == null || !this.rpConfig.equals(other.rpConfig))) {
                return false;
            }
            
            if (this.ssoConfig != other.ssoConfig && (this.ssoConfig == null || !this.ssoConfig.equals(other.ssoConfig))) {
                return false;
            }
            
            if (this.spDescriptor != other.spDescriptor && (this.spDescriptor == null || !this.spDescriptor.equals(other.spDescriptor))) {
                return false;
            }
            
            if (this.assertionConsumerService != other.assertionConsumerService && (this.assertionConsumerService == null || !this.assertionConsumerService.equals(other.assertionConsumerService))) {
                return false;
            }
            
            return true;
        }
        
        public int hashCode() {
            int hash = 7;
            return hash;
        }
        
        
    }
    
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(AbstractAuthenticationRequest.class);
    
    /** HttpSession key for the AuthenticationRequestContext. */
    protected static final String REQUEST_CONTEXT_SESSION_KEY = "edu.internet2.middleware.shibboleth.idp.profile.saml2.AuthenticationRequestContext";
    
    /** The path to the IdP's AuthenticationManager servlet */
    protected String authnMgrURL;
    
    /** AuthenticationManager to be used */
    protected AuthenticationManager authnMgr;
    
    /** A pool of XML parsers. */
    protected ParserPool parserPool;
    
    /** Builder for AuthnStatements. */
    protected SAMLObjectBuilder<AuthnStatement> authnStatementBuilder;
    
    /** Builder for AuthnContexts. */
    protected SAMLObjectBuilder<AuthnContext> authnContextBuilder;
    
    /** Builder for AuthnContextDeclRef's */
    protected SAMLObjectBuilder<AuthnContextDeclRef> authnContextDeclRefBuilder;
    
    /** Builder for AuthnContextClassRef's. */
    protected SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder;
    
    /**
     * Constructor.
     */
    public AbstractAuthenticationRequest() {
        
        parserPool = new BasicParserPool();
        authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) getBuilderFactory().getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) getBuilderFactory().getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContextDeclRefBuilder = (SAMLObjectBuilder<AuthnContextDeclRef>) getBuilderFactory().getBuilder(AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
        authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) getBuilderFactory().getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    }
    
    /**
     * Set the Authentication Mananger.
     *
     * @param authnManager
     *            The IdP's AuthenticationManager.
     */
    public void setAuthenticationManager(AuthenticationManager authnManager) {
        this.authnMgr = authnMgr;
    }
    
    /**
     * Evaluate a SAML 2 AuthenticationRequest message.
     *
     * @param authnRequest
     *            A SAML 2 AuthenticationRequest
     * @param issuer
     *            The issuer of the authnRequest.
     * @param session
     *            The HttpSession of the request.
     * @param relyingParty
     *            The RelyingPartyConfiguration for the request.
     * @param ssoConfig
     *            The SSOConfiguration for the request.
     * @param spDescriptor
     *            The SPSSODescriptor for the request.
     *
     * @throws ProfileException
     *             On Error.
     */
    protected void evaluateRequest(final AuthenticationRequestContext requestContext) throws ProfileException {
        
        Response samlResponse;
        
        final AuthnRequest authnRequest = requestContext.getAuthnRequest();
        String issuer = requestContext.getIssuer();
        final HttpSession session = requestContext.getHttpSession();
        final RelyingPartyConfiguration relyingParty = requestContext.getRpConfig();
        final SSOConfiguration ssoConfig = requestContext.getSsoConfig();
        final SPSSODescriptor spDescriptor = requestContext.getSpDescriptor();
        
        LoginContext loginCtx = requestContext.getLoginContext();
        if (loginCtx.getAuthenticationOK()) {
            
            // the user successfully authenticated.
            // build an authentication assertion.
            samlResponse = buildResponse(authnRequest.getID(), new DateTime(),
                    relyingParty.getProviderId(), buildStatus(StatusCode.SUCCESS_URI, null, null));
            
            DateTime now = new DateTime();
            Assertion assertion = buildAssertion(now, relyingParty, (AbstractSAML2ProfileConfiguration) ssoConfig);
            assertion.setSubject(requestContext.getSubject());
            setAuthenticationStatement(assertion, loginCtx, authnRequest);
            samlResponse.getAssertions().add(assertion);
            
        } else {
            
            // if authentication failed, encode the appropriate SAML error message.
            String failureMessage = loginCtx.getAuthenticationFailureMessage();
            Status failureStatus = buildStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI, failureMessage);
            samlResponse = buildResponse(authnRequest.getID(), new DateTime(), relyingParty.getProviderId(),
                    failureStatus);
        }
        
        requestContext.setResponse(samlResponse);
    }
    
    /**
     * Build a SAML 2 Response element with basic fields populated.
     *
     * Failure handlers can send the returned response element to the RP.
     * Success handlers should add the assertions before sending it.
     *
     * @param inResponseTo
     *            The ID of the request this is in response to.
     * @param issueInstant
     *            The timestamp of this response.
     * @param issuer
     *            The URI of the RP issuing the response.
     * @param status
     *            The response's status code.
     *
     * @return The populated Response object.
     */
    protected Response buildResponse(String inResponseTo,
            final DateTime issueInstant, String issuer, final Status status) {
        
        Response response = getResponseBuilder().buildObject();
        
        Issuer i = getIssuerBuilder().buildObject();
        i.setValue(issuer);
        
        response.setVersion(SAML_VERSION);
        response.setID(getIdGenerator().generateIdentifier());
        response.setInResponseTo(inResponseTo);
        response.setIssueInstant(issueInstant);
        response.setIssuer(i);
        response.setStatus(status);
        
        return response;
    }
    
    /**
     * Check if the user has already been authenticated.
     *
     * @param httpSession
     *            the user's HttpSession.
     *
     * @return <code>true</code> if the user has been authenticated. otherwise
     *         <code>false</code>
     */
    protected boolean hasUserAuthenticated(final HttpSession httpSession) {
        
        // if the user has authenticated, their session will have a LoginContext
        
        Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        return (o != null && o instanceof LoginContext);
    }
    
    /**
     * Check if the user has already been authenticated. If so, return the
     * LoginContext. If not, redirect the user to the AuthenticationManager.
     *
     * @param authnRequest
     *            The SAML 2 AuthnRequest.
     * @param httpSession
     *            The user's HttpSession.
     * @param request
     *            The user's HttpServletRequest.
     * @param response
     *            The user's HttpServletResponse.
     *
     * @throws ProfileException
     *             on error.
     */
    protected void authenticateUser(final AuthenticationRequestContext requestContext) throws ProfileException {
        
        AuthnRequest authnRequest = requestContext.getAuthnRequest();
        HttpSession httpSession = requestContext.getHttpSession();
        HttpServletRequest servletRequest = requestContext.getServletRequest();
        HttpServletResponse servletResponse = requestContext.getServletResponse();
        
        // Forward the request to the AuthenticationManager.
        // When the AuthenticationManager is done it will
        // forward the request back to this servlet.
        
        // push the AuthenticationRequestContext into the session so we have it
        // for the return leg.
        httpSession.setAttribute(REQUEST_CONTEXT_SESSION_KEY, requestContext);
        
        Saml2LoginContext loginCtx = new Saml2LoginContext(authnRequest);
        requestContext.setLoginContext(loginCtx);
        loginCtx.setProfileHandlerURL(servletRequest.getRequestURI());
        
        // the AuthenticationManager expects the LoginContext to be in the HttpSession.
        httpSession.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginCtx);
        try {
            RequestDispatcher dispatcher = servletRequest
                    .getRequestDispatcher(authnMgrURL);
            dispatcher.forward(servletRequest,servletResponse);
        } catch (IOException ex) {
            log.error("Error forwarding SAML 2 AuthnRequest "
                    + authnRequest.getID() + " to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding SAML 2 AuthnRequest "
                    + authnRequest.getID() + " to AuthenticationManager", ex);
        } catch (ServletException ex) {
            log.error("Error forwarding SAML 2 AuthnRequest "
                    + authnRequest.getID() + " to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding SAML 2 AuthnRequest "
                    + authnRequest.getID() + " to AuthenticationManager", ex);
        }
    }
    
    /**
     * Build an AuthnStatement and add it to an Assertion.
     *
     * @param assertion An empty SAML 2 Assertion object.
     * @param loginContext The processed login context for the AuthnRequest.
     * @param authnRequest The AuthnRequest to which this is in response.
     *
     * @throws ProfileException On error.
     */
    protected void setAuthenticationStatement(Assertion assertion,
            final LoginContext loginContext,
            final AuthnRequest authnRequest) throws ProfileException {
        
        // Build the AuthnCtx.
        // We need to determine if the user was authenticated
        // with an AuthnContextClassRef or a AuthnContextDeclRef
        AuthnContext authnCtx = buildAuthnCtx(authnRequest.getRequestedAuthnContext(), loginContext);
        if (authnCtx == null) {
            log.error("Error respond to SAML 2 AuthnRequest "
                    + authnRequest.getID()
                    + " : Unable to determine authentication method");
        }
        
        AuthnStatement stmt = authnStatementBuilder.buildObject();
        stmt.setAuthnInstant(loginContext.getAuthenticationInstant());
        stmt.setAuthnContext(authnCtx);
        
        // add the AuthnStatement to the Assertion
        List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
        authnStatements.add(stmt);
    }
    
    /**
     * Create the AuthnContex object.
     *
     * To do this, we have to walk the AuthnRequest's RequestedAuthnContext
     * object and compare any values we find to what's set in the loginContext.
     *
     * @param requestedAuthnCtx
     *            The RequestedAuthnContext from the Authentication Request.
     * @param loginContext
     *            The processed LoginContext (it must contain the authn method).
     *
     * @return An AuthnCtx object on success or <code>null</code> on failure.
     */
    protected AuthnContext buildAuthnCtx(
            final RequestedAuthnContext requestedAuthnCtx,
            final LoginContext loginContext) {
        
        // this method assumes that only one URI will match.
        
        AuthnContext authnCtx = authnContextBuilder.buildObject();
        String authnMethod = loginContext.getAuthenticationMethod();
        
        List<AuthnContextClassRef> authnClasses = requestedAuthnCtx
                .getAuthnContextClassRefs();
        List<AuthnContextDeclRef> authnDeclRefs = requestedAuthnCtx
                .getAuthnContextDeclRefs();
        
        if (authnClasses != null) {
            for (AuthnContextClassRef classRef : authnClasses) {
                if (classRef != null) {
                    String s = classRef.getAuthnContextClassRef();
                    if (s != null && authnMethod.equals(s)) {
                        AuthnContextClassRef ref = authnContextClassRefBuilder
                                .buildObject();
                        authnCtx.setAuthnContextClassRef(ref);
                        return authnCtx;
                    }
                }
            }
        }
        
        // if no AuthnContextClassRef's matched, try the DeclRefs
        if (authnDeclRefs != null) {
            for (AuthnContextDeclRef declRef : authnDeclRefs) {
                if (declRef != null) {
                    String s = declRef.getAuthnContextDeclRef();
                    if (s != null && authnMethod.equals((s))) {
                        AuthnContextDeclRef ref = authnContextDeclRefBuilder
                                .buildObject();
                        authnCtx.setAuthnContextDeclRef(ref);
                        return authnCtx;
                    }
                }
            }
        }
        
        // no matches were found.
        return null;
    }
    
    /**
     * Verify the AuthnRequest is well-formed.
     *
     * @param authnRequest
     *            The user's SAML 2 AuthnRequest.
     * @param issuer
     *            The Issuer of the AuthnRequest.
     * @param relyingParty
     *            The relying party configuration for the request's originator.
     * @param session
     *            The user's HttpSession.
     *
     * @throws AuthenticationRequestException
     *             on error.
     */
    protected void verifyAuthnRequest(final AuthenticationRequestContext requestContext) throws AuthenticationRequestException {
        
        final AuthnRequest authnRequest = requestContext.getAuthnRequest();
        String issuer = requestContext.getIssuer();
        final RelyingPartyConfiguration relyingParty = requestContext.getRpConfig();
        final HttpSession session = requestContext.getHttpSession();
        
        Status failureStatus;
        
        // Check if we are in scope to handle this AuthnRequest
        checkScope(authnRequest, issuer);
        
        // verify that the AssertionConsumerService url is valid.
        verifyAssertionConsumerService(requestContext,
                getRelyingPartyConfigurationManager().getMetadataProvider());
        
        // check for nameID constraints.
        verifySubject(requestContext);
    }
    
    /**
     * Get and verify the Subject element.
     *
     * @param requestContext The context for the current request.
     * 
     * @throws AuthenticationRequestException
     *             on error.
     */
    protected void verifySubject(final AuthenticationRequestContext requestContext)
            throws AuthenticationRequestException {
        
        final AuthnRequest authnRequest = requestContext.getAuthnRequest();
        
        Status failureStatus;
        
        Subject subject = authnRequest.getSubject();
        
        if (subject == null) {
            failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
                    "SAML 2 AuthnRequest " + authnRequest.getID()
                    + " is malformed: It does not contain a Subject.");
            throw new AuthenticationRequestException(
                    "AuthnRequest lacks a Subject", failureStatus);
        }
        
        // The Web Browser SSO profile disallows SubjectConfirmation
        // methods in the requested subject.
        List<SubjectConfirmation> confMethods = subject
                .getSubjectConfirmations();
        if (confMethods != null || confMethods.size() > 0) {
            log
                    .error("SAML 2 AuthnRequest "
                    + authnRequest.getID()
                    + " is malformed: It contains SubjectConfirmation elements.");
            failureStatus = buildStatus(
                    StatusCode.REQUESTER_URI,
                    null,
                    "SAML 2 AuthnRequest "
                    + authnRequest.getID()
                    + " is malformed: It contains SubjectConfirmation elements.");
            throw new AuthenticationRequestException(
                    "AuthnRequest contains SubjectConfirmation elements",
                    failureStatus);
        }
        
        requestContext.setSubject(subject);
        
        return;
    }
    
    /**
     * Ensure that metadata can be found for the SP that issued
     * the AuthnRequest.
     *
     * If found, the request context is updated to reflect the appropriate entries.
     *
     * Before this method may be called, the request context must have an issuer set.
     *
     * @param requestContext The context for the current request.
     *
     * @throws AuthenticationRequestException On error.
     */
    protected void validateRequestAgainstMetadata(final AuthenticationRequestContext requestContext) throws AuthenticationRequestException {
        
        RelyingPartyConfiguration relyingParty = null;
        SSOConfiguration ssoConfig = null;
        SPSSODescriptor spDescriptor = null;
        
        // check that we have metadata for the RP
        relyingParty = getRelyingPartyConfigurationManager().getRelyingPartyConfiguration(requestContext.getIssuer());
        
        ProfileConfiguration temp = relyingParty.getProfileConfigurations().get(SSOConfiguration.PROFILE_ID);
        if (temp == null) {
            log.error("SAML 2 Authentication Request: No profile configuration registered for " + SSOConfiguration.PROFILE_ID);
            throw new AuthenticationRequestException("No profile configuration registered for " + SSOConfiguration.PROFILE_ID);
        }
        
        ssoConfig = (SSOConfiguration) temp;
        
        try {
            spDescriptor = getMetadataProvider().getEntityDescriptor(
                    relyingParty.getRelyingPartyId()).getSPSSODescriptor(
                    SAML20_PROTOCOL_URI);
        } catch (MetadataProviderException ex) {
            log.error(
                    "SAML 2 Authentication Request: Unable to locate SPSSODescriptor for SP "
                    + requestContext.getIssuer() + " for protocol " + SAML20_PROTOCOL_URI, ex);
            
            Status failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
                    "No metadata available for " + relyingParty.getRelyingPartyId());
            
            throw new AuthenticationRequestException("SAML 2 Authentication Request: Unable to locate SPSSODescriptor for SP "
                    + requestContext.getIssuer() + " for protocol " + SAML20_PROTOCOL_URI, ex, failureStatus);
        }
        
        if (spDescriptor == null) {
            log.error("SAML 2 Authentication Request: Unable to locate SPSSODescriptor for SP "
                    + requestContext.getIssuer() + " for protocol " + SAML20_PROTOCOL_URI);

            Status failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
                    "No metadata available for " + relyingParty.getRelyingPartyId());
            
            throw new AuthenticationRequestException("SAML 2 Authentication Request: Unable to locate SPSSODescriptor for SP "
                    + requestContext.getIssuer() + " for protocol " + SAML20_PROTOCOL_URI, failureStatus);
        }
        
        // if all metadata was found, update the request context.
        requestContext.setRpConfig(relyingParty);
        requestContext.setSsoConfig(ssoConfig);
        requestContext.setSpDescriptor(spDescriptor);
    }
    
    /**
     * Return the endpoint URL and protocol binding to use for the AuthnRequest.
     *
     * @param requestContext The context for the current request.
     * 
     * @param metadata
     *            The appropriate Metadata.
     *
     * @throws AuthenticationRequestException
     *             On error.
     */
    protected void verifyAssertionConsumerService(
            final AuthenticationRequestContext requestContext,
            
            final MetadataProvider metadata)
            throws AuthenticationRequestException {
        
        Status failureStatus;
        
        final AuthnRequest authnRequest = requestContext.getAuthnRequest();
        String providerId = requestContext.getRpConfig().getRelyingPartyId();
        
        // Either the AssertionConsumerServiceIndex must be present
        // or AssertionConsumerServiceURL must be present.
        
        Integer idx = authnRequest.getAssertionConsumerServiceIndex();
        String acsURL = authnRequest.getAssertionConsumerServiceURL();
        
        if (idx != null && acsURL != null) {
            log
                    .error("SAML 2 AuthnRequest "
                    + authnRequest.getID()
                    + " is malformed: It contains both an AssertionConsumerServiceIndex and an AssertionConsumerServiceURL");
            failureStatus = buildStatus(
                    StatusCode.REQUESTER_URI,
                    null,
                    "SAML 2 AuthnRequest "
                    + authnRequest.getID()
                    + " is malformed: It contains both an AssertionConsumerServiceIndex and an AssertionConsumerServiceURL");
            throw new AuthenticationRequestException("Malformed AuthnRequest",
                    failureStatus);
        }
        
        SPSSODescriptor spDescriptor;
        try {
            spDescriptor = metadata.getEntityDescriptor(providerId)
                    .getSPSSODescriptor(SAML20_PROTOCOL_URI);
        } catch (MetadataProviderException ex) {
            log.error(
                    "Unable retrieve SPSSODescriptor metadata for providerId "
                    + providerId
                    + " while processing SAML 2 AuthnRequest "
                    + authnRequest.getID(), ex);
            failureStatus = buildStatus(StatusCode.RESPONDER_URI, null,
                    "Unable to locate metadata for " + providerId);
            throw new AuthenticationRequestException(
                    "Unable to locate metadata", ex, failureStatus);
        }
        
        List<AssertionConsumerService> acsList = spDescriptor
                .getAssertionConsumerServices();
        
        // if the ACS index is specified, retrieve it from the metadata
        if (idx != null) {
            
            int i = idx.intValue();
            
            // if the index is out of range, return an appropriate error.
            if (i > acsList.size()) {
                log.error("Illegal AssertionConsumerIndex specicifed (" + i
                        + ") in SAML 2 AuthnRequest " + authnRequest.getID());
                
                failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
                        "Illegal AssertionConsumerIndex specicifed (" + i
                        + ") in SAML 2 AuthnRequest "
                        + authnRequest.getID());
                
                throw new AuthenticationRequestException(
                        "Illegal AssertionConsumerIndex in AuthnRequest",
                        failureStatus);
            }
            
            requestContext.setAssertionConsumerService(acsList.get(i));
            return;
        }
        
        // if the ACS endpoint is specified, validate it against the metadata
        String protocolBinding = authnRequest.getProtocolBinding();
        for (AssertionConsumerService acs : acsList) {
            if (acsURL.equals(acs.getLocation())) {
                if (protocolBinding != null) {
                    if (protocolBinding.equals(acs.getBinding())) {
                        requestContext.setAssertionConsumerService(acs);
                        return;
                    }
                }
            }
        }
        
        log
                .error("Error processing SAML 2 AuthnRequest message "
                + authnRequest.getID()
                + ": Unable to validate AssertionConsumerServiceURL against metadata: "
                + acsURL + " for binding " + protocolBinding);
        
        failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
                "Unable to validate AssertionConsumerService against metadata.");
        
        throw new AuthenticationRequestException(
                "SAML 2 AuthenticationRequest: Unable to validate AssertionConsumerService against Metadata",
                failureStatus);
    }
    
    /**
     * Check if an {@link AuthnRequest} contains a {@link Scoping} element. If
     * so, check if the specified IdP is in the {@link IDPList} element. If no
     * Scoping element is present, this method returns <code>true</code>.
     *
     * @param authnRequest
     *            The {@link AuthnRequest} element to check.
     * @param providerId
     *            The IdP's ProviderID.
     *
     * @throws AuthenticationRequestException
     *             on error.
     */
    protected void checkScope(final AuthnRequest authnRequest, String providerId)
            throws AuthenticationRequestException {
        
        Status failureStatus;
        
        List<String> idpEntries = new LinkedList<String>();
        
        Scoping scoping = authnRequest.getScoping();
        if (scoping == null) {
            return;
        }
        
        // process all of the explicitly listed idp provider ids
        IDPList idpList = scoping.getIDPList();
        if (idpList == null) {
            return;
        }
        
        List<IDPEntry> explicitIDPEntries = idpList.getIDPEntrys();
        if (explicitIDPEntries != null) {
            for (IDPEntry entry : explicitIDPEntries) {
                String s = entry.getProviderID();
                if (s != null) {
                    idpEntries.add(s);
                }
            }
        }
        
        // If the IDPList is incomplete, retrieve the complete list
        // and add the entries to idpEntries.
        GetComplete getComplete = idpList.getGetComplete();
        IDPList referencedIdPs = getCompleteIDPList(getComplete);
        if (referencedIdPs != null) {
            List<IDPEntry> referencedIDPEntries = referencedIdPs.getIDPEntrys();
            if (referencedIDPEntries != null) {
                for (IDPEntry entry : referencedIDPEntries) {
                    String s = entry.getProviderID();
                    if (s != null) {
                        idpEntries.add(s);
                    }
                }
            }
        }
        
        // iterate over all the IDPEntries we've gathered,
        // and check if we're in scope.
        for (String requestProviderId : idpEntries) {
            if (providerId.equals(requestProviderId)) {
                log.debug("Found Scoping match for IdP: (" + providerId + ")");
                return;
            }
        }
        
        log.error("SAML 2 AuthnRequest " + authnRequest.getID()
                + " contains a Scoping element which "
                + "does not contain a providerID registered with this IdP.");
        
        failureStatus = buildStatus(StatusCode.RESPONDER_URI,
                StatusCode.NO_SUPPORTED_IDP_URI, null);
        throw new AuthenticationRequestException(
                "Unrecognized providerID in Scoping element", failureStatus);
    }
    
    /**
     * Retrieve an incomplete IDPlist.
     *
     * This only handles URL-based <GetComplete/> references.
     *
     * @param getComplete
     *            The (possibly <code>null</code>) &lt;GetComplete/&gt;
     *            element
     *
     * @return an {@link IDPList} or <code>null</code> if the uri can't be
     *         dereferenced.
     */
    protected IDPList getCompleteIDPList(final GetComplete getComplete) {
        
        // XXX: enhance this method to cache the url and last-modified-header
        
        if (getComplete == null) {
            return null;
        }
        
        String uri = getComplete.getGetComplete();
        if (uri != null) {
            return null;
        }
        
        IDPList idpList = null;
        InputStream istream = null;
        
        try {
            URL url = new URL(uri);
            URLConnection conn = url.openConnection();
            istream = conn.getInputStream();
            
            // convert the raw data into an XML object
            Document doc = parserPool.parse(istream);
            Element docElement = doc.getDocumentElement();
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory()
                    .getUnmarshaller(docElement);
            idpList = (IDPList) unmarshaller.unmarshall(docElement);
            
        } catch (MalformedURLException ex) {
            log.error(
                    "Unable to retrieve GetComplete IDPList. Unsupported URI: "
                    + uri, ex);
        } catch (IOException ex) {
            log.error("IO Error while retreieving GetComplete IDPList from "
                    + uri, ex);
        } catch (XMLParserException ex) {
            log.error(
                    "Internal OpenSAML error while parsing GetComplete IDPList from "
                    + uri, ex);
        } catch (UnmarshallingException ex) {
            log.error(
                    "Internal OpenSAML error while unmarshalling GetComplete IDPList from "
                    + uri, ex);
        } finally {
            
            if (istream != null) {
                try {
                    istream.close();
                } catch (IOException ex) {
                    // pass
                }
            }
        }
        
        return idpList;
    }
    
    /**
     * Encode a SAML Response.
     *
     * @param binding The SAML protocol binding to use.
     * @param requestContext The context for the request.
     *
     * @throws ProfileException On error.
     */
    protected void encodeResponse(String binding,
            final AuthenticationRequestContext requestContext) throws ProfileException {
        
        final ProfileResponse<ServletResponse> profileResponse = requestContext.getProfileResponse();
        final Response samlResponse = requestContext.getResponse();
        final RelyingPartyConfiguration relyingParty = requestContext.getRpConfig();
        final RoleDescriptor roleDescriptor = requestContext.getSpDescriptor();
        final Endpoint endpoint = requestContext.getAssertionConsumerService();
        
        
        MessageEncoder<ServletResponse> encoder = getMessageEncoderFactory().getMessageEncoder(binding);
        if (encoder == null) {
            log.error("No MessageEncoder registered for " + binding);
            throw new ProfileException("No MessageEncoder registered for " + binding);
        }
        
        encoder.setResponse(profileResponse.getRawResponse());
        encoder.setIssuer(relyingParty.getProviderId());
        encoder.setMetadataProvider(getRelyingPartyConfigurationManager().getMetadataProvider());
        encoder.setRelyingPartyRole(roleDescriptor);
        encoder.setSigningCredential(relyingParty.getDefaultSigningCredential());
        encoder.setSamlMessage(samlResponse);
        encoder.setRelyingPartyEndpoint(endpoint);
        
        try {
            encoder.encode();
        } catch (BindingException ex) {
            log.error("Unable to encode response the relying party: " + relyingParty.getRelyingPartyId(), ex);
            throw new ProfileException("Unable to encode response the relying party: "
                    + relyingParty.getRelyingPartyId(), ex);
        }
        
    }
    
}
