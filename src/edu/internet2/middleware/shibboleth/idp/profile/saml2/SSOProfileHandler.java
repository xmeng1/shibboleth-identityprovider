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

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.AuthnResponseEndpointSelector;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectLocality;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;
import edu.internet2.middleware.shibboleth.common.util.HttpHelper;
import edu.internet2.middleware.shibboleth.idp.authn.ForceAuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.PassiveAuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/** SAML 2.0 SSO request profile handler. */
public class SSOProfileHandler extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SSOProfileHandler.class);

    /** Builder of AuthnStatement objects. */
    private SAMLObjectBuilder<AuthnStatement> authnStatementBuilder;

    /** Builder of AuthnContext objects. */
    private SAMLObjectBuilder<AuthnContext> authnContextBuilder;

    /** Builder of AuthnContextClassRef objects. */
    private SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder;

    /** Builder of AuthnContextDeclRef objects. */
    private SAMLObjectBuilder<AuthnContextDeclRef> authnContextDeclRefBuilder;

    /** Builder of SubjectLocality objects. */
    private SAMLObjectBuilder<SubjectLocality> subjectLocalityBuilder;

    /** URL of the authentication manager servlet. */
    private String authenticationManagerPath;

    /** URI of request decoder. */
    private String decodingBinding;

    /**
     * Constructor.
     * 
     * @param authnManagerPath path to the authentication manager servlet
     */
    @SuppressWarnings("unchecked")
    public SSOProfileHandler(String authnManagerPath) {
        super();

        authenticationManagerPath = authnManagerPath;

        authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) getBuilderFactory().getBuilder(
                AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) getBuilderFactory().getBuilder(
                AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) getBuilderFactory().getBuilder(
                AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextDeclRefBuilder = (SAMLObjectBuilder<AuthnContextDeclRef>) getBuilderFactory().getBuilder(
                AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
        subjectLocalityBuilder = (SAMLObjectBuilder<SubjectLocality>) getBuilderFactory().getBuilder(
                SubjectLocality.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml2:request:sso";
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        HttpServletRequest servletRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        HttpSession httpSession = servletRequest.getSession(true);
        LoginContext loginContext = (LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);

        if (loginContext == null) {
            log.debug("User session does not contain a login context, processing as first leg of request");
            performAuthentication(inTransport, outTransport);
        } else if (!loginContext.isPrincipalAuthenticated() && !loginContext.getAuthenticationAttempted()) {
            log
                    .debug("User session contained a login context but user was not authenticated, processing as first leg of request");
            performAuthentication(inTransport, outTransport);
        } else {
            log.debug("User session contains a login context, processing as second leg of request");
            completeAuthenticationRequest(inTransport, outTransport);
        }
    }

    /**
     * Creates a {@link Saml2LoginContext} an sends the request off to the AuthenticationManager to begin the process of
     * authenticating the user.
     * 
     * @param inTransport inbound request transport
     * @param outTransport outbound response transport
     * 
     * @throws ProfileException thrown if there is a problem creating the login context and transferring control to the
     *             authentication manager
     */
    protected void performAuthentication(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        HttpServletRequest servletRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        HttpSession httpSession = servletRequest.getSession();

        try {
            SSORequestContext requestContext = decodeRequest(inTransport, outTransport);

            String relyingPartyId = requestContext.getInboundMessageIssuer();
            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
            ProfileConfiguration ssoConfig = rpConfig.getProfileConfiguration(SSOConfiguration.PROFILE_ID);
            if (ssoConfig == null) {
                log.error("SAML 2 SSO profile is not configured for relying party "
                        + requestContext.getInboundMessageIssuer());
                throw new ProfileException("SAML 2 SSO profile is not configured for relying party "
                        + requestContext.getInboundMessageIssuer());
            }

            log.debug("Creating login context and transferring control to authentication engine");
            Saml2LoginContext loginContext = new Saml2LoginContext(relyingPartyId, requestContext.getRelayState(),
                    requestContext.getInboundSAMLMessage());
            loginContext.setAuthenticationEngineURL(authenticationManagerPath);
            loginContext.setProfileHandlerURL(HttpHelper.getRequestUriWithoutContext(servletRequest));
            if (loginContext.getRequestedAuthenticationMethods().size() == 0) {
                loginContext.getRequestedAuthenticationMethods().add(rpConfig.getDefaultAuthenticationMethod());
            }

            httpSession.setAttribute(Saml2LoginContext.LOGIN_CONTEXT_KEY, loginContext);
            RequestDispatcher dispatcher = servletRequest.getRequestDispatcher(authenticationManagerPath);
            dispatcher.forward(servletRequest, ((HttpServletResponseAdapter) outTransport).getWrappedResponse());
        } catch (MarshallingException e) {
            httpSession.removeAttribute(LoginContext.LOGIN_CONTEXT_KEY);
            log.error("Unable to marshall authentication request context");
            throw new ProfileException("Unable to marshall authentication request context", e);
        } catch (IOException ex) {
            httpSession.removeAttribute(LoginContext.LOGIN_CONTEXT_KEY);
            log.error("Error forwarding SAML 2 AuthnRequest to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding SAML 2 AuthnRequest to AuthenticationManager", ex);
        } catch (ServletException ex) {
            httpSession.removeAttribute(LoginContext.LOGIN_CONTEXT_KEY);
            log.error("Error forwarding SAML 2 AuthnRequest to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding SAML 2 AuthnRequest to AuthenticationManager", ex);
        }
    }

    /**
     * Creates a response to the {@link AuthnRequest} and sends the user, with response in tow, back to the relying
     * party after they've been authenticated.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @throws ProfileException thrown if the response can not be created and sent back to the relying party
     */
    protected void completeAuthenticationRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        HttpServletRequest servletRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        HttpSession httpSession = servletRequest.getSession();

        Saml2LoginContext loginContext = (Saml2LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        httpSession.removeAttribute(LoginContext.LOGIN_CONTEXT_KEY);

        SSORequestContext requestContext = buildRequestContext(loginContext, inTransport, outTransport);

        checkSamlVersion(requestContext);

        Response samlResponse;
        try {
            if (loginContext.getAuthenticationFailure() != null) {
                log.error("User authentication failed with the following error: {}", loginContext
                        .getAuthenticationFailure().toString());

                if (loginContext.getAuthenticationFailure() instanceof PassiveAuthenticationException) {
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.NO_PASSIVE_URI,
                            null));
                } else {
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI,
                            null));
                }
            }

            if (requestContext.getSubjectNameIdentifier() != null) {
                log
                        .debug("Authentication request contained a subject with a name identifier, resolving principal from NameID");
                resolvePrincipal(requestContext);
                String requestedPrincipalName = requestContext.getPrincipalName();
                if (!DatatypeHelper.safeEquals(loginContext.getPrincipalName(), requestedPrincipalName)) {
                    log
                            .error(
                                    "Authentication request identified principal {} but authentication mechanism identified principal {}",
                                    requestedPrincipalName, loginContext.getPrincipalName());
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI,
                            null));
                    throw new ProfileException("User failed authentication");
                }
            }

            resolveAttributes(requestContext);

            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAuthnStatement(requestContext));
            if (requestContext.getProfileConfiguration().includeAttributeStatement()) {
                AttributeStatement attributeStatement = buildAttributeStatement(requestContext);
                if (attributeStatement != null) {
                    requestContext.setRequestedAttributes(requestContext.getPrincipalAttributes().keySet());
                    statements.add(attributeStatement);
                }
            }

            samlResponse = buildResponse(requestContext, "urn:oasis:names:tc:SAML:2.0:cm:bearer", statements);
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext);
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Decodes an incoming request and stores the information in a created request context.
     * 
     * @param inTransport inbound transport
     * @param outTransport outbound transport
     * 
     * @return request context with decoded information
     * 
     * @throws ProfileException thrown if the incoming message failed decoding
     */
    protected SSORequestContext decodeRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        log.debug("Decoding message with decoder binding {}", getInboundBinding());
        SSORequestContext requestContext = new SSORequestContext();
        requestContext.setMetadataProvider(getMetadataProvider());
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());

        requestContext.setCommunicationProfileId(SSOConfiguration.PROFILE_ID);
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        try {
            SAMLMessageDecoder decoder = getMessageDecoders().get(getInboundBinding());
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded request");

            if (!(requestContext.getInboundMessage() instanceof AuthnRequest)) {
                log.error("Incomming message was not a AuthnRequest, it was a {}", requestContext.getInboundMessage()
                        .getClass().getName());
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
                        "Invalid SAML AuthnRequest message."));
                throw new ProfileException("Invalid SAML AuthnRequest message.");
            }

            return requestContext;
        } catch (MessageDecodingException e) {
            log.error("Error decoding authentication request message", e);
            throw new ProfileException("Error decoding authentication request message", e);
        } catch (SecurityException e) {
            log.error("Message did not meet security requirements", e);
            throw new ProfileException("Message did not meet security requirements", e);
        }
    }

    /**
     * Creates an authentication request context from the current environmental information.
     * 
     * @param loginContext current login context
     * @param in inbound transport
     * @param out outbount transport
     * 
     * @return created authentication request context
     * 
     * @throws ProfileException thrown if there is a problem creating the context
     */
    protected SSORequestContext buildRequestContext(Saml2LoginContext loginContext, HTTPInTransport in,
            HTTPOutTransport out) throws ProfileException {
        SSORequestContext requestContext = new SSORequestContext();

        requestContext.setMessageDecoder(getMessageDecoders().get(getInboundBinding()));

        requestContext.setLoginContext(loginContext);
        requestContext.setPrincipalName(loginContext.getPrincipalName());
        requestContext.setPrincipalAuthenticationMethod(loginContext.getAuthenticationMethod());
        requestContext.setUserSession(getUserSession(in));
        requestContext.setRelayState(loginContext.getRelayState());

        requestContext.setInboundMessageTransport(in);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        try {
            AuthnRequest authnRequest = loginContext.getAuthenticationRequest();
            requestContext.setInboundMessage(authnRequest);
            requestContext.setInboundSAMLMessage(loginContext.getAuthenticationRequest());
            requestContext.setInboundSAMLMessageId(loginContext.getAuthenticationRequest().getID());

            Subject authnSubject = authnRequest.getSubject();
            if (authnSubject != null) {
                requestContext.setSubjectNameIdentifier(authnSubject.getNameID());
            }
        } catch (UnmarshallingException e) {
            log.error("Unable to unmarshall authentication request context");
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Error recovering request state"));
            throw new ProfileException("Error recovering request state", e);
        }

        requestContext.setOutboundMessageTransport(out);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        MetadataProvider metadataProvider = getMetadataProvider();
        requestContext.setMetadataProvider(metadataProvider);

        String relyingPartyId = loginContext.getRelyingPartyId();
        requestContext.setInboundMessageIssuer(relyingPartyId);
        try {
            EntityDescriptor relyingPartyMetadata = metadataProvider.getEntityDescriptor(relyingPartyId);
            if (relyingPartyMetadata != null) {
                requestContext.setPeerEntityMetadata(relyingPartyMetadata);
                requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setPeerEntityRoleMetadata(relyingPartyMetadata
                        .getSPSSODescriptor(SAMLConstants.SAML20P_NS));
            } else {
                log.error("Unable to locate metadata for relying party ({})", relyingPartyId);
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                        "Error locating relying party metadata"));
                throw new ProfileException("Error locating relying party metadata");
            }
        } catch (MetadataProviderException e) {
            log.error("Unable to locate metadata for relying party");
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Error locating relying party metadata"));
            throw new ProfileException("Error locating relying party metadata");
        }

        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
        if (rpConfig == null) {
            log.error("Unable to retrieve relying party configuration data for entity with ID {}", relyingPartyId);
            throw new ProfileException("Unable to retrieve relying party configuration data for entity with ID "
                    + relyingPartyId);
        }
        requestContext.setRelyingPartyConfiguration(rpConfig);

        SSOConfiguration profileConfig = (SSOConfiguration) rpConfig
                .getProfileConfiguration(SSOConfiguration.PROFILE_ID);
        requestContext.setProfileConfiguration(profileConfig);
        requestContext.setOutboundMessageArtifactType(profileConfig.getOutboundArtifactType());
        requestContext.setPeerEntityEndpoint(selectEndpoint(requestContext));

        String assertingPartyId = rpConfig.getProviderId();
        requestContext.setLocalEntityId(assertingPartyId);
        requestContext.setOutboundMessageIssuer(assertingPartyId);
        try {
            EntityDescriptor localEntityDescriptor = metadataProvider.getEntityDescriptor(assertingPartyId);
            if (localEntityDescriptor != null) {
                requestContext.setLocalEntityMetadata(localEntityDescriptor);
                requestContext.setLocalEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setLocalEntityRoleMetadata(localEntityDescriptor
                        .getIDPSSODescriptor(SAMLConstants.SAML20P_NS));
            }
        } catch (MetadataProviderException e) {
            log.error("Unable to locate metadata for asserting party");
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Error locating asserting party metadata"));
            throw new ProfileException("Error locating asserting party metadata");
        }

        return requestContext;
    }

    /**
     * Creates an authentication statement for the current request.
     * 
     * @param requestContext current request context
     * 
     * @return constructed authentication statement
     */
    protected AuthnStatement buildAuthnStatement(SSORequestContext requestContext) {
        Saml2LoginContext loginContext = requestContext.getLoginContext();

        AuthnContext authnContext = buildAuthnContext(requestContext);

        AuthnStatement statement = authnStatementBuilder.buildObject();
        statement.setAuthnContext(authnContext);
        statement.setAuthnInstant(loginContext.getAuthenticationInstant());

        Session session = getUserSession(requestContext.getInboundMessageTransport());
        if (session != null) {
            statement.setSessionIndex(session.getSessionID());
        }

        if (loginContext.getAuthenticationDuration() > 0) {
            statement.setSessionNotOnOrAfter(loginContext.getAuthenticationInstant().plus(
                    loginContext.getAuthenticationDuration()));
        }

        statement.setSubjectLocality(buildSubjectLocality(requestContext));

        return statement;
    }

    /**
     * Creates an {@link AuthnContext} for a succesful authentication request.
     * 
     * @param requestContext current request
     * 
     * @return the built authn context
     */
    protected AuthnContext buildAuthnContext(SSORequestContext requestContext) {
        AuthnContext authnContext = authnContextBuilder.buildObject();

        Saml2LoginContext loginContext = requestContext.getLoginContext();
        AuthnRequest authnRequest = requestContext.getInboundSAMLMessage();
        RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
        if (requestedAuthnContext != null) {
            if (requestedAuthnContext.getAuthnContextClassRefs() != null) {
                for (AuthnContextClassRef classRef : requestedAuthnContext.getAuthnContextClassRefs()) {
                    if (classRef.getAuthnContextClassRef().equals(loginContext.getAuthenticationMethod())) {
                        AuthnContextClassRef ref = authnContextClassRefBuilder.buildObject();
                        ref.setAuthnContextClassRef(loginContext.getAuthenticationMethod());
                        authnContext.setAuthnContextClassRef(ref);
                    }
                }
            } else if (requestedAuthnContext.getAuthnContextDeclRefs() != null) {
                for (AuthnContextDeclRef declRef : requestedAuthnContext.getAuthnContextDeclRefs()) {
                    if (declRef.getAuthnContextDeclRef().equals(loginContext.getAuthenticationMethod())) {
                        AuthnContextDeclRef ref = authnContextDeclRefBuilder.buildObject();
                        ref.setAuthnContextDeclRef(loginContext.getAuthenticationMethod());
                        authnContext.setAuthnContextDeclRef(ref);
                    }
                }
            }
        } else {
            AuthnContextDeclRef ref = authnContextDeclRefBuilder.buildObject();
            ref.setAuthnContextDeclRef(loginContext.getAuthenticationMethod());
            authnContext.setAuthnContextDeclRef(ref);
        }

        return authnContext;
    }

    /**
     * Constructs the subject locality for the authentication statement.
     * 
     * @param requestContext curent request context
     * 
     * @return subject locality for the authentication statement
     */
    protected SubjectLocality buildSubjectLocality(SSORequestContext requestContext) {
        HTTPInTransport transport = (HTTPInTransport) requestContext.getInboundMessageTransport();
        SubjectLocality subjectLocality = subjectLocalityBuilder.buildObject();
        subjectLocality.setAddress(transport.getPeerAddress());
        subjectLocality.setDNSName(transport.getPeerDomainName());

        return subjectLocality;
    }

    /**
     * Selects the appropriate endpoint for the relying party and stores it in the request context.
     * 
     * @param requestContext current request context
     * 
     * @return Endpoint selected from the information provided in the request context
     */
    protected Endpoint selectEndpoint(SSORequestContext requestContext) {
        AuthnResponseEndpointSelector endpointSelector = new AuthnResponseEndpointSelector();
        endpointSelector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        endpointSelector.setMetadataProvider(getMetadataProvider());
        endpointSelector.setEntityMetadata(requestContext.getPeerEntityMetadata());
        endpointSelector.setEntityRoleMetadata(requestContext.getPeerEntityRoleMetadata());
        endpointSelector.setSamlRequest(requestContext.getInboundSAMLMessage());
        endpointSelector.getSupportedIssuerBindings().addAll(getSupportedOutboundBindings());
        return endpointSelector.selectEndpoint();
    }

    /** Represents the internal state of a SAML 2.0 SSO Request while it's being processed by the IdP. */
    protected class SSORequestContext extends BaseSAML2ProfileRequestContext<AuthnRequest, Response, SSOConfiguration> {

        /** Current login context. */
        private Saml2LoginContext loginContext;

        /**
         * Gets the current login context.
         * 
         * @return current login context
         */
        public Saml2LoginContext getLoginContext() {
            return loginContext;
        }

        /**
         * Sets the current login context.
         * 
         * @param context current login context
         */
        public void setLoginContext(Saml2LoginContext context) {
            loginContext = context;
        }
    }
}