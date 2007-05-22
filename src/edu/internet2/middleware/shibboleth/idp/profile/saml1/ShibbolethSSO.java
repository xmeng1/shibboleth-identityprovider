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
import edu.internet2.middleware.shibboleth.common.relyingparty.saml1.ShibbolethSSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import java.io.UnsupportedEncodingException;

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
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.signature.SignableXMLObject;

/**
 * Shibboleth, version 1.X, single sign-on profile handler.
 *
 * This profile implements the SSO profile from "Shibboleth Architecture Protocols and Profiles" - 10 September 2005.
 */
public class ShibbolethSSO extends AbstractSAML1ProfileHandler {
    
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
    
    /** Builder for Status objects. */
    protected SAMLObjectBuilder<Status> statusBuilder;
    
    /** Builder for StatusCode objects. */
    protected SAMLObjectBuilder<StatusCode> statusCodeBuilder;
    
    /** Builder for StatusMessage objects. */
    protected SAMLObjectBuilder<StatusMessage> statusMessageBuilder;
    
    /** Builder for Response objects. */
    protected SAMLObjectBuilder<Response> responseBuilder;
    
    /** Block stale requests. */
    protected boolean blockStaleRequests = false;
    
    /** Blame the SP if requests are malformed. */
    protected boolean blameSP = false;
    
    /**
     * Time after which an authn request is considered stale(in seconds). Defaults to 30 minutes.
     */
    protected int requestTTL = 1800;
    
    /** Protocol binding to use to the Authentication Assertion */
    protected enum ENDPOINT_BINDING {
        BROWSER_POST, ARTIFACT
    };
    
    /** PRNG for Artifact assertionHandles. */
    protected SecureRandom prng;
    
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
        statusBuilder              = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder          = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder       = (SAMLObjectBuilder<StatusMessage>) getBuilderFactory().getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
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
            // xxx: throw exception
            return;
        }
        
        HttpServletRequest httpRequest = (HttpServletRequest) request.getRawRequest();
        HttpServletResponse httpResponse = (HttpServletResponse) response.getRawResponse();
        HttpSession httpSession = httpRequest.getSession();
        LoginContext loginCtx;
        
        String shire = null;
        String target = null;
        String providerId = null;
        String remoteAddr = null;
        
        // extract the (mandatory) request parameters.
        if (!getRequestParameters(httpRequest, shire, target, providerId, remoteAddr)) {
            
            if (blameSP) {
                httpRequest.setAttribute("errorPage", "/IdPErrorBlameSP.jsp");
                // XXX: flesh this out more.
            }
            
            // xxx: throw exception;
            return;
        }
        
        // check for stale requests
        if (blockStaleRequests) {
            String cookieName = getRPCookieName(providerId);
            if (!validateFreshness(httpRequest, httpResponse, cookieName)) {
                // xxX: log error and throw exception
                return;
            }
            
            writeFreshnessCookie(httpRequest,httpResponse, cookieName);
        }
        
        // check if the user has already been authenticated
        Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        if (o == null) {
            
            // the user hasn't been authenticated, so forward the request
            // to the AuthenticationManager. When the AuthenticationManager
            // is done it will forward the request back to this servlet.
            
            // don't force reauth or passive auth
            loginCtx = new LoginContext(false, false);
            loginCtx.setProfileHandlerURL(httpRequest.getPathInfo());
            httpSession.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginCtx);
            try {
                RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(authnMgrURL);
                dispatcher.forward(httpRequest, httpResponse);
            } catch (IOException ex) {
                log.error("Error forwarding SAML 1 SSO request to AuthenticationManager", ex);
                throw new ProfileException("Error forwarding SAML 1 SSO request to AuthenticationManager", ex);
            } catch (ServletException ex) {
                log.error("Error forwarding SAML 1 SSO request to AuthenticationManager", ex);
                throw new ProfileException("Error forwarding SAML 1 SSO request to AuthenticationManager", ex);
            }
        }
        
        // The user has been authenticated.
        // Process the SAML 1 authn request.
        
        if (!(o instanceof LoginContext)) {
            log.error("Invalid login context object -- object is not an instance of LoginContext.");
            // xxx: throw exception
            return;
        }
        
        loginCtx = (LoginContext) o;
        
        if (!loginCtx.getAuthenticationOK()) {
            // issue error message.
            String failureMessage = loginCtx.getAuthenticationFailureMessage();
            
            // generate SAML failure message
            
            return;
        }
        
        // The user successfully authenticated,
        // so build the appropriate AuthenticationStatement.
        
        DateTime now = new DateTime();
        RelyingPartyConfiguration relyingParty = getRelyingPartyConfigurationManager().getRelyingPartyConfiguration(providerId);
        ProfileConfiguration temp = relyingParty.getProfileConfigurations().get(ShibbolethSSOConfiguration.PROFILE_ID);
        if (temp == null) {
            log.error("No profile configuration registered for " + ShibbolethSSOConfiguration.PROFILE_ID);
            throw new ProfileException("No profile configuration registered for " + ShibbolethSSOConfiguration.PROFILE_ID);
        }
        
        ShibbolethSSOConfiguration ssoConfig = (ShibbolethSSOConfiguration) temp;
        SPSSODescriptor spDescriptor;
        
        try {
            spDescriptor = getMetadataProvider().getEntityDescriptor(relyingParty.getRelyingPartyId()).getSPSSODescriptor(SAML11_PROTOCOL_URI);
        } catch (MetadataProviderException ex) {
            log.error("Unable to locate metadata for SP " + providerId + " for protocol " + SAML11_PROTOCOL_URI, ex);
            // xxx: throw exception
            return;
        }
        
        if (spDescriptor == null) {
            log.error("Unable to locate metadata for SP " + providerId + " for protocol " + SAML11_PROTOCOL_URI);
            // handle error
            return;
        }
        
        // validate the AssertionConsumer URL
        List<AssertionConsumerService> consumerEndpoints = validateAssertionConsumerURL(spDescriptor, shire);
        if (consumerEndpoints.size() == 0) {
            // handle error
            return;
        }
        
        ENDPOINT_BINDING endpointBinding = getProtocolBinding(spDescriptor, consumerEndpoints, shire);
        
        String confMethod = null;
        if (endpointBinding.equals(ENDPOINT_BINDING.BROWSER_POST)) {
            confMethod = BEARER_CONF_METHOD_URI;
        } else if (endpointBinding.equals(ENDPOINT_BINDING.ARTIFACT)) {
            confMethod = ARTIFACT_CONF_METHOD_URI;
        }
        
        Assertion authenticationAssertion = generateAuthenticationAssertion(loginCtx, relyingParty, ssoConfig,
                providerId, spDescriptor, confMethod, now);
        if (authenticationAssertion == null) {
            // do error handling
            return;
        }
        
        if (endpointBinding.equals(ENDPOINT_BINDING.BROWSER_POST)) {
            // do post
        } else if (endpointBinding.equals(ENDPOINT_BINDING.ARTIFACT)) {
            //respondWithArtifact(httpRequest, httpResponse, shire, target, new Assertion[] { authenticationAssertion });
        }
        
        return;
    }
    
    /**
     * Respond with a SAML Artifact.
     *
     * @param request The HttpServletRequest.
     * @param response The HttpServletResponse.
     * @param shire The AssertionConsumerService URL.
     * @parma target The target parameter from the request.
     * @param assertions One or more SAML assertions.
     */
    protected void respondWithArtifact(HttpServletRequest request, HttpServletResponse response, String shire,
            String target, RelyingPartyConfiguration relyingParty, Assertion[] assertions) throws ProfileException,
            NoSuchProviderException {
        
        //        if (assertions.length < 1) {
        //            return;
        //        }
        //
        //        StringBuilder buf = new StringBuilder(shire);
        //        buf.append("?TARGET=");
        //        buf.append(URLEncoder.encode(target), "UTF-8");;
        //
        //        // We construct the type 1 Artifact's sourceID by SHA-1 hashing the
        //        // IdP's providerID.
        //        // This is legacy holdover from Shib 1.x.
        //        MessageDigest digester = MessageDigest.getInstance("SHA-1");
        //        byte[] sourceID = digester.digest(relyingParty.getProviderID);
        //
        //        for (Assertion assertion : assertions) {
        //
        //            // XXX: todo: log the assertion to log4j @ debug level.
        //
        //            byte artifactType = (byte) relyingParty.getDefaultArtifactType();
        //
        //            SAMLArtifact artifact = artifactFactory.buildArtifact(SAML_VERSION, new byte[] { 0, artifactType },
        //                    relyingParty.getProviderID());
        //
        //            String artifactID = artifact.hexEncode();
        //            artifactMap.put(artifact, assertion);
        //
        //            log.debug("encoding assertion " + assertion.getID() + " into artifact " + artifactID);
        //            log.debug("appending artifact " + artifactID + " for URL " + shire);
        //            buf.append("&SAMLArt=");
        //            buf.append(URLEncoder.encode(artifact.base64Encode(), "UTF-8"));
        //        }
        //
        //        String url = buf.toString();
        //        response.sendRedirect(url);
    }
    
    /**
     * Respond with the SAML 1 Browser/POST profile.
     *
     * @param request The HttpServletRequest.
     * @param response The HttpServletResponse.
     * @param shire The AssertionConsumerService URL.
     * @parma target The target parameter from the request.
     * @param assertions One or more SAML assertions.
     */
    protected void respondWithPOST(HttpServletRequest request, HttpServletResponse response, String shire,
            String target, RelyingPartyConfiguration relyingParty, Assertion[] assertions) throws ProfileException {
        
        //        Response samlResponse = (Response) responseBuilder.buildObject(Response.DEFAULT_ELEMENT_NAME);
        //        Status status = buildStatus("Success", null);
        //        samlResponse.setStatus(status);
        //        samlResponse.setIssueInstant(new DateTime());
        //        samlResponse.setVersion(SAML_VERSION);
        //        samlResponse.setID(getIdGenerator().generateIdentifier());
        //        samlResponse.setRecipient(relyingParty.getRelyingPartyID());
        //
        //        List<Assertion> assertionList = samlResponse.getAssertions();
        //        for (Assertion assertion : assertions) {
        //            assertionList.add(assertion);
        //        }
        //
        //        request.setAttribute("acceptanceURL", shire);
        //        request.setAttribute("target", target);
        //
        //        RequestDispatcher dispatcher = request.getRequestDispatcher("/IdP_SAML1_POST.jdp");
        //        dispatcher.forward(request, response);
    }
    
    /**
     * Get the Shibboleth profile-specific request parameters. The shire, target, providerId and remoteAddr parameters
     * will be populated upon successful return.
     *
     * @param request The servlet request from the SP.
     * @param shire The AttributeConsumerService URL
     * @param target The location to which to POST the response.
     * @param providerId The SP's provider ID in the metadata.
     * @param remoteAddr The address of the requestor.
     *
     * @return <code>true</code> if the request contains valid parameters.
     */
    protected boolean getRequestParameters(HttpServletRequest request, String shire, String target, String providerId,
            String remoteAddr) {
        
        target = request.getParameter("target");
        providerId = request.getParameter("providerId");
        shire = request.getParameter("shire");
        remoteAddr = request.getRemoteAddr();
        
        if (target == null || target.equals("")) {
            log.error("Shib 1 SSO request is missing or contains an invalid target parameter");
            return false;
        }
        
        if (providerId == null || providerId.equals("")) {
            log.error("Shib 1 SSO request is missing or contains an invalid provierId parameter");
            return false;
        }
        
        if (shire == null || providerId.equals("")) {
            log.error("Shib 1 SSO request is missing or contains an invalid shire parameter");
            return false;
        }
        
        if (remoteAddr == null || remoteAddr.equals("")) {
            log.error("Unable to obtain requestor address when processing Shib 1 SSO request");
            return false;
        }
        
        return true;
    }
    
    /**
     * Generate a SAML 1 AuthenticationStatement.
     *
     * @param loginCtx The LoginContext.
     * @param relyingParty The Replying Party configuration for the SP.
     * @param ssoConfig The ShibbolethSSOConfiguration data.
     * @param spID The providerID of the SP that sent the request.
     * @param spDescriptor The SPSSO Descriptor from the metadata.
     * @param subjectConfirmationMethod The SubjectConfirmationMethod. If <code>null</code> no
     *            SubjectConfirmationMethod element will be generated.
     * @param now The current timestamp
     *
     * @return A SAML 1 Authentication Assertion or <code>null</code> on error.
     */
    protected Assertion generateAuthenticationAssertion(final LoginContext loginCtx,
            final RelyingPartyConfiguration relyingParty, final ShibbolethSSOConfiguration ssoConfig, String spID,
            final SPSSODescriptor spDescriptor, String subjectConfirmationMethod, final DateTime now) {
        
        Assertion authenticationAssertion = assertionBuilder.buildObject();
        authenticationAssertion.setIssueInstant(now);
        authenticationAssertion.setVersion(SAMLVersion.VERSION_11);
        authenticationAssertion.setIssuer(relyingParty.getProviderId());
        authenticationAssertion.setID(getIdGenerator().generateIdentifier());
        
        Conditions conditions = authenticationAssertion.getConditions();
        conditions.setNotBefore(now.minusSeconds(30)); // for now, clock skew is hard-coded to 30 seconds.
        conditions.setNotOnOrAfter(now.plusMillis((int)ssoConfig.getAssertionLifetime()));
        
        List<AudienceRestrictionCondition> audienceRestrictions = conditions.getAudienceRestrictionConditions();
        AudienceRestrictionCondition restrictionCondition = audienceRestrictionBuilder.buildObject();
        audienceRestrictions.add(restrictionCondition);
        
        // add the RelyingParty to the audience.
        Audience rpAudience = audienceBuilder.buildObject();
        rpAudience.setUri(relyingParty.getProviderId());
        restrictionCondition.getAudiences().add(rpAudience);
        
        // if necessary, explicitely add the SP to the audience.
        if (!relyingParty.getProviderId().equals(spID)) {
            Audience spAudience = (Audience) audienceBuilder.buildObject();
            spAudience.setUri(spID);
            restrictionCondition.getAudiences().add(spAudience);
        }
        
        AuthenticationStatement authenticationStatement = authnStmtBuilder.buildObject();
        authenticationStatement.setSubject(buildSubject(loginCtx, subjectConfirmationMethod, ssoConfig));
        authenticationStatement.setAuthenticationInstant(loginCtx.getAuthenticationInstant());
        authenticationStatement.setAuthenticationMethod(authenticationMethodURI);
        
        authenticationAssertion.getAuthenticationStatements().add(authenticationStatement);
        
        if (spDescriptor.getWantAssertionsSigned()) {
            // xxx: sign the assertion
        }
        
        return authenticationAssertion;
    }
    
    /**
     * Get the protocol binding to use for sending the authentication assertion. Currently, only Browser/POST and
     * Artifact are supported. This method will return the first recognized binding that it locates.
     *
     * @param spDescriptor The SP's SPSSODescriptor
     * @param endpoints The list of AssertionConsumerEndpoints with the "shire" URL as their location.
     * @param shireURL The "shire" url from the authn request.
     *
     * @return The protocol binding for a given SPSSODescriptor.
     *
     * @throws ProfileException if no Browswer/POST or Artifact binding can be found.
     */
    protected ENDPOINT_BINDING getProtocolBinding(final SPSSODescriptor spDescriptor,
            final List<AssertionConsumerService> endpoints, String shireURL) throws ProfileException {
        
        // check the default AssertionConsumerService first.
        AssertionConsumerService defaultConsumer = spDescriptor.getDefaultAssertionConsumerService();
        
        if (defaultConsumer != null && defaultConsumer.getLocation().equals(shireURL)) {
            
            if (defaultConsumer.getBinding().equals(PROFILE_ARTIFACT_URI)) {
                return ENDPOINT_BINDING.ARTIFACT;
            } else if (defaultConsumer.getBinding().equals(PROFILE_BROWSER_POST_URI)) {
                return ENDPOINT_BINDING.BROWSER_POST;
            }
        }
        
        // check the (already filtered) list of AssertionConsumer endpoints
        for (AssertionConsumerService endpoint : endpoints) {
            if (endpoint.getBinding().equals(PROFILE_ARTIFACT_URI)) {
                return ENDPOINT_BINDING.ARTIFACT;
            } else if (endpoint.getBinding().equals(PROFILE_BROWSER_POST_URI)) {
                return ENDPOINT_BINDING.BROWSER_POST;
            }
        }
        
        // no AssertionConsumerServices were found, or none had a recognized
        // binding
        log.error("Unable to find a Browswer/POST or Artifact binding " + " for an AssertionConsumerService in "
                + spDescriptor.getID());
        
        throw new ProfileException("Unable to find a Browswer/POST or Artifact binding "
                + " for an AssertionConsumerService in " + spDescriptor.getID());
    }
    
    /**
     * Sign an {@link XMLObject}.
     *
     * @param object The XMLObject to be signed.
     *
     * @throws KeyException On error.
     */
    protected void signXMLObject(final SignableXMLObject object) throws KeyException {
        // sign the object
    }
    
    /**
     * Validate the AssertionConsumer ("shire") URL against the metadata.
     *
     * @param spDescriptor The SPSSO element from the metadata
     * @param url The "shire" URL.
     *
     * @return a {@link List} of AssertionConsumerServices which have <code>url</code> as their location.
     */
    protected List<AssertionConsumerService> validateAssertionConsumerURL(final SPSSODescriptor spDescriptor, String url) {
        
        // spDescriptor returns a reference to an
        // internal mutable copy, so make a copy of it.
        List<AssertionConsumerService> consumerURLs =
                new ArrayList<AssertionConsumerService>(spDescriptor.getAssertionConsumerServices().size());
        
        // filter out any list elements that don't have the correct location field.
        // copy any consumerURLs with the correct location
        for (AssertionConsumerService service : spDescriptor.getAssertionConsumerServices()) {
            if (service.getLocation().equals(url)) {
                consumerURLs.add(service);
            }
        }
        
        return consumerURLs;
    }
    
    /**
     * Validate the "freshness" of an authn request. If the reqeust is more than 30 minutes old, reject it.
     *
     * @param request The HttpServletRequest
     * @param response The HttpServletResponse
     * @param cookieName The name of the RP's cookie.
     *
     * @return <code>true</code> if the cookie is fresh; otherwise <code>false</code>
     *
     * @throws ProfileException On error.
     */
    protected boolean validateFreshness(HttpServletRequest request, HttpServletResponse response, String cookieName)
            throws ProfileException {
        
        try {
            if (cookieName == null) {
                return false;
            }
            
            String timestamp = request.getParameter("time");
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
            
            if (reqtime * 1000 < System.currentTimeMillis() - requestTTL * 1000) {
                RequestDispatcher rd = request.getRequestDispatcher("/IdPStale.jsp");
                rd.forward(request, response);
                return false;
            }
            
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    try {
                        long cookieTime = Long.parseLong(cookie.getValue());
                        if (reqtime <= cookieTime) {
                            RequestDispatcher rd = request.getRequestDispatcher("/IdPStale.jsp");
                            rd.forward(request, response);
                            return false;
                        }
                    } catch (NumberFormatException ex) {
                        log.error("Unable to parse freshness cookie's timestamp", ex);
                        return false;
                    }
                }
            }
            
            return true;
        } catch (IOException ex) {
            throw new ProfileException("Error validating freshness cookie", ex);
        } catch (ServletException ex) {
            throw new ProfileException("Error validating freshness cookie", ex);
        }
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
     */
    protected void writeFreshnessCookie(HttpServletRequest request, HttpServletResponse response, String cookieName) {
        
        String timestamp = request.getParameter("time");
        if (timestamp == null || timestamp.equals("")) {
            return;
        }
        
        Cookie cookie = new Cookie(cookieName, timestamp);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }
    
    /**
     * Generate a SAML 1 Subject element.
     *
     * @param loginContext The LoginContext for an authenticated user.
     * @param confirmationMethod The SubjectConfirmationMethod URI, or <code>null</code> is none is to be set.
     * @param ssoConfig The ShibbolethSSO configuration for the request.
     *
     * @return a Subject object.
     */
    protected Subject buildSubject(final LoginContext loginCtx, String confirmationMethod,
            final ShibbolethSSOConfiguration ssoConfig) {
        
        Subject subject = subjectBuilder.buildObject();
        
        NameIdentifier nameID = nameIdentifierBuilder.buildObject();
        nameID.setFormat(ssoConfig.getDefaultNameIDFormat());
        String username = loginCtx.getUserID();
        // XXX: todo: map the username onto an appropriate format
        nameID.setNameQualifier(username);
        
        if (confirmationMethod != null) {
            
            SubjectConfirmation subjConf = (SubjectConfirmation) subjConfBuilder
                    .buildObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
            
            ConfirmationMethod m = (ConfirmationMethod) confMethodBuilder
                    .buildObject(ConfirmationMethod.DEFAULT_ELEMENT_NAME);
            
            m.setConfirmationMethod(confirmationMethod);
            subjConf.getConfirmationMethods().add(m);
            subject.setSubjectConfirmation(subjConf);
        }
        
        return subject;
    }
    
    /**
     * Build a SAML 1 Status element.
     *
     * @param statusCode The status code - see oasis-sstc-saml-core-1.1, section 3.4.3.1.
     * @param statusMessage The status message, or <code>null</code> if none is to be set.
     *
     * @return The Status object, or <code>null</code> on error.
     */
    protected Status buildStatus(String statusCode, String statusMessage) {
        
        if (statusCode == null || statusCode.equals("")) {
            return null;
        }
        
        Status status = (Status) statusBuilder.buildObject(Status.DEFAULT_ELEMENT_NAME);
        StatusCode sc = (StatusCode) statusCodeBuilder.buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
        sc.setValue(statusCode);
        status.setStatusCode(sc);
        
        if (statusMessage != null || !(statusMessage.equals(""))) {
            
            StatusMessage sm = (StatusMessage) statusMessageBuilder.buildObject(StatusMessage.DEFAULT_ELEMENT_NAME);
            sm.setMessage(statusMessage);
            status.setStatusMessage(sm);
        }
        
        return status;
    }
    
    /**
     * Get an Attribute Statement.
     *
     * @param rpConfig The RelyingPartyConfiguration for the request.
     * @param subject The Subject of the request.
     * @param request The ServletRequest.
     *
     * @return An AttributeStatement.
     *
     * @throws ProfileException On error.
     */
    protected AttributeStatement getAttributeStatement(RelyingPartyConfiguration rpConfig, Subject subject,
            ServletRequest request) throws ProfileException {
        //
        //        // build a dummy AttributeQuery object for the AA.
        //
        //        AttributeAuthority aa = new AttributeAuthority();
        //        aa.setAttributeResolver(getAttributeResolver());
        //        aa.setFilteringEngine(getFilteringEngine());
        //        // aa.setSecurityPolicy(getDecoder().getSecurityPolicy()); //
        //        // super.getDecoder() will need to change.
        //        aa.setRequest(request);
        //        aa.setRelyingPartyConfiguration(rpConfig);
        //        AttributeStatement statement = null;
        //        try {
        //            statement = aa.performAttributeQuery(message);
        //        } catch (AttributeResolutionException e) {
        //            log.error("Error resolving attributes", e);
        //            throw new ServletException("Error resolving attributes");
        //        } catch (FilteringException e) {
        //            log.error("Error filtering attributes", e);
        //            throw new ServletException("Error filtering attributes");
        //        }
        //
        //        return statement;
        
        return null;
    }
}