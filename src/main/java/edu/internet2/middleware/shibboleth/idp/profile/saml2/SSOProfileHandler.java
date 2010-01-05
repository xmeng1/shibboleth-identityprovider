/*
 * Copyright 2007 University Corporation for Advanced Internet Development, Inc.
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
import java.io.StringReader;
import java.util.ArrayList;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.Configuration;
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
import org.opensaml.saml2.core.NameID;
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
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.MessageFormatter;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.common.util.HttpHelper;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.PassiveAuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.session.impl.ServiceInformationImpl;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

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

    /** Builder of Endpoint objects. */
    private SAMLObjectBuilder<Endpoint> endpointBuilder;

    /** URL of the authentication manager Servlet. */
    private String authenticationManagerPath;

    /**
     * Constructor.
     * 
     * @param authnManagerPath path to the authentication manager Servlet
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
        endpointBuilder = (SAMLObjectBuilder<Endpoint>) getBuilderFactory().getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return SSOConfiguration.PROFILE_ID;
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();

        LoginContext loginContext = HttpServletHelper.getLoginContext(httpRequest);
        if (loginContext == null) {
            log.debug("Incoming request does not contain a login context, processing as first leg of request");
            performAuthentication(inTransport, outTransport);
        } else {
            log.debug("Incoming request contains a login context, processing as second leg of request");
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
        SSORequestContext requestContext = new SSORequestContext();

        try {
            decodeRequest(requestContext, inTransport, outTransport);

            String relyingPartyId = requestContext.getInboundMessageIssuer();
            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
            ProfileConfiguration ssoConfig = rpConfig.getProfileConfiguration(getProfileId());
            if (ssoConfig == null) {
                String msg = MessageFormatter.format("SAML 2 SSO profile is not configured for relying party '{}'",
                        requestContext.getInboundMessageIssuer());
                log.warn(msg);
                throw new ProfileException(msg);
            }

            log.debug("Creating login context and transferring control to authentication engine");
            Saml2LoginContext loginContext = new Saml2LoginContext(relyingPartyId, requestContext.getRelayState(),
                    requestContext.getInboundSAMLMessage());
            loginContext.setAuthenticationEngineURL(authenticationManagerPath);
            loginContext.setProfileHandlerURL(HttpHelper.getRequestUriWithoutContext(servletRequest));
            loginContext.setDefaultAuthenticationMethod(rpConfig.getDefaultAuthenticationMethod());

            HttpServletHelper.bindLoginContext(loginContext, servletRequest);
            RequestDispatcher dispatcher = servletRequest.getRequestDispatcher(authenticationManagerPath);
            dispatcher.forward(servletRequest, ((HttpServletResponseAdapter) outTransport).getWrappedResponse());
        } catch (MarshallingException e) {
            log.error("Unable to marshall authentication request context");
            throw new ProfileException("Unable to marshall authentication request context", e);
        } catch (IOException ex) {
            log.error("Error forwarding SAML 2 AuthnRequest to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding SAML 2 AuthnRequest to AuthenticationManager", ex);
        } catch (ServletException ex) {
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
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        Saml2LoginContext loginContext = (Saml2LoginContext) HttpServletHelper.getLoginContext(httpRequest);

        SSORequestContext requestContext = buildRequestContext(loginContext, inTransport, outTransport);

        checkSamlVersion(requestContext);

        Response samlResponse;
        try {
            if (loginContext.getAuthenticationFailure() != null) {
                if (loginContext.getAuthenticationFailure() instanceof PassiveAuthenticationException) {
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.NO_PASSIVE_URI,
                            null));
                } else {
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI,
                            null));
                }
                throw new ProfileException("Authentication failure", loginContext.getAuthenticationFailure());
            }

            if (requestContext.getSubjectNameIdentifier() != null) {
                log.debug("Authentication request contained a subject with a name identifier, resolving principal from NameID");
                resolvePrincipal(requestContext);
                String requestedPrincipalName = requestContext.getPrincipalName();
                if (!DatatypeHelper.safeEquals(loginContext.getPrincipalName(), requestedPrincipalName)) {
                    log.warn("Authentication request identified principal {} but authentication mechanism identified principal {}",
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
                    requestContext.setReleasedAttributes(requestContext.getAttributes().keySet());
                    statements.add(attributeStatement);
                }
            }

            samlResponse = buildResponse(requestContext, "urn:oasis:names:tc:SAML:2.0:cm:bearer", statements);

            //bind nameID to session.servicesInformation
            NameID nameID = buildNameId(requestContext);
            Session session =
                    getUserSession(requestContext.getInboundMessageTransport());
            ServiceInformationImpl serviceInfo =
                    (ServiceInformationImpl) session.getServicesInformation().get(requestContext.getPeerEntityId());
            serviceInfo.setSAML2NameIdentifier(nameID);
            //index session by nameid
            SessionManager<Session> sessionManager = getSessionManager();
            String index = sessionManager.getIndexFromNameID(nameID);
            if (index != null) {
                sessionManager.indexSession(session, index);
            }
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
     * @param requestContext request context to which decoded information should be added
     * 
     * @throws ProfileException thrown if the incoming message failed decoding
     */
    protected void decodeRequest(SSORequestContext requestContext, HTTPInTransport inTransport,
            HTTPOutTransport outTransport) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Decoding message with decoder binding '{}'", getInboundMessageDecoder(requestContext)
                    .getBindingURI());
        }

        requestContext.setCommunicationProfileId(getProfileId());

        requestContext.setMetadataProvider(getMetadataProvider());
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());

        requestContext.setCommunicationProfileId(getProfileId());
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        try {
            SAMLMessageDecoder decoder = getInboundMessageDecoder(requestContext);
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded request from relying party '{}'", requestContext.getInboundMessageIssuer());

            if (!(requestContext.getInboundSAMLMessage() instanceof AuthnRequest)) {
                log.warn("Incomming message was not a AuthnRequest, it was a '{}'", requestContext
                        .getInboundSAMLMessage().getClass().getName());
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
                        "Invalid SAML AuthnRequest message."));
                throw new ProfileException("Invalid SAML AuthnRequest message.");
            }
        } catch (MessageDecodingException e) {
            String msg = "Error decoding authentication request message";
            log.warn(msg, e);
            throw new ProfileException(msg, e);
        } catch (SecurityException e) {
            String msg = "Message did not meet security requirements";
            log.warn(msg, e);
            throw new ProfileException(msg, e);
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
        requestContext.setCommunicationProfileId(getProfileId());

        requestContext.setMessageDecoder(getInboundMessageDecoder(requestContext));

        requestContext.setLoginContext(loginContext);

        requestContext.setInboundMessageTransport(in);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        requestContext.setOutboundMessageTransport(out);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        requestContext.setMetadataProvider(getMetadataProvider());

        String relyingPartyId = loginContext.getRelyingPartyId();
        requestContext.setPeerEntityId(relyingPartyId);
        requestContext.setInboundMessageIssuer(relyingPartyId);

        populateRequestContext(requestContext);

        return requestContext;
    }

    /** {@inheritDoc} */
    protected void populateRelyingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateRelyingPartyInformation(requestContext);

        EntityDescriptor relyingPartyMetadata = requestContext.getPeerEntityMetadata();
        if (relyingPartyMetadata != null) {
            requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setPeerEntityRoleMetadata(relyingPartyMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    /** {@inheritDoc} */
    protected void populateAssertingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateAssertingPartyInformation(requestContext);

        EntityDescriptor localEntityDescriptor = requestContext.getLocalEntityMetadata();
        if (localEntityDescriptor != null) {
            requestContext.setLocalEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setLocalEntityRoleMetadata(localEntityDescriptor
                    .getIDPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    /**
     * Populates the request context with information from the inbound SAML message.
     * 
     * This method requires the the following request context properties to be populated: login context
     * 
     * This methods populates the following request context properties: inbound saml message, relay state, inbound saml
     * message ID, subject name identifier
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the inbound SAML message or subject identifier is null
     */
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        SSORequestContext ssoRequestContext = (SSORequestContext) requestContext;
        try {
            Saml2LoginContext loginContext = ssoRequestContext.getLoginContext();
            requestContext.setRelayState(loginContext.getRelayState());

            AuthnRequest authnRequest = deserializeRequest(loginContext.getAuthenticationRequest());
            requestContext.setInboundMessage(authnRequest);
            requestContext.setInboundSAMLMessage(authnRequest);
            requestContext.setInboundSAMLMessageId(authnRequest.getID());

            Subject authnSubject = authnRequest.getSubject();
            if (authnSubject != null) {
                requestContext.setSubjectNameIdentifier(authnSubject.getNameID());
            }
        } catch (UnmarshallingException e) {
            log.error("Unable to unmarshall authentication request context");
            ssoRequestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Error recovering request state"));
            throw new ProfileException("Error recovering request state", e);
        }
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

        long maxSPSessionLifetime = requestContext.getProfileConfiguration().getMaximumSPSessionLifetime();
        if (maxSPSessionLifetime > 0) {
            DateTime lifetime = new DateTime(DateTimeZone.UTC).plus(maxSPSessionLifetime);
            log.debug("Explicitly setting SP session expiration time to '{}'", lifetime.toString());
            statement.setSessionNotOnOrAfter(lifetime);
        }

        statement.setSubjectLocality(buildSubjectLocality(requestContext));

        return statement;
    }

    /**
     * Creates an {@link AuthnContext} for a successful authentication request.
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
        }

        if (authnContext.getAuthnContextClassRef() == null || authnContext.getAuthnContextDeclRef() == null) {
            AuthnContextClassRef ref = authnContextClassRefBuilder.buildObject();
            ref.setAuthnContextClassRef(loginContext.getAuthenticationMethod());
            authnContext.setAuthnContextClassRef(ref);
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

        return subjectLocality;
    }

    /**
     * Selects the appropriate endpoint for the relying party and stores it in the request context.
     * 
     * @param requestContext current request context
     * 
     * @return Endpoint selected from the information provided in the request context
     */
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) {
        AuthnRequest authnRequest = ((SSORequestContext) requestContext).getInboundSAMLMessage();

        Endpoint endpoint = null;
        if (requestContext.getRelyingPartyConfiguration().getRelyingPartyId() == SAMLMDRelyingPartyConfigurationManager.ANONYMOUS_RP_NAME) {
            if (authnRequest.getAssertionConsumerServiceURL() != null) {
                endpoint = endpointBuilder.buildObject();
                endpoint.setLocation(authnRequest.getAssertionConsumerServiceURL());
                if (authnRequest.getProtocolBinding() != null) {
                    endpoint.setBinding(authnRequest.getProtocolBinding());
                } else {
                    endpoint.setBinding(getSupportedOutboundBindings().get(0));
                }
                log
                        .warn(
                                "Generating endpoint for anonymous relying party self-identified as '{}', ACS url '{}' and binding '{}'",
                                new Object[] { requestContext.getInboundMessageIssuer(), endpoint.getLocation(),
                                        endpoint.getBinding(), });
            } else {
                log.warn("Unable to generate endpoint for anonymous party.  No ACS url provided.");
            }
        } else {
            AuthnResponseEndpointSelector endpointSelector = new AuthnResponseEndpointSelector();
            endpointSelector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
            endpointSelector.setMetadataProvider(getMetadataProvider());
            endpointSelector.setEntityMetadata(requestContext.getPeerEntityMetadata());
            endpointSelector.setEntityRoleMetadata(requestContext.getPeerEntityRoleMetadata());
            endpointSelector.setSamlRequest(requestContext.getInboundSAMLMessage());
            endpointSelector.getSupportedIssuerBindings().addAll(getSupportedOutboundBindings());
            endpoint = endpointSelector.selectEndpoint();
        }

        return endpoint;
    }

    /**
     * Deserailizes an authentication request from a string.
     * 
     * @param request request to deserialize
     * 
     * @return the request XMLObject
     * 
     * @throws UnmarshallingException thrown if the request can no be deserialized and unmarshalled
     */
    protected AuthnRequest deserializeRequest(String request) throws UnmarshallingException {
        try {
            Element requestElem = getParserPool().parse(new StringReader(request)).getDocumentElement();
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(requestElem);
            return (AuthnRequest) unmarshaller.unmarshall(requestElem);
        } catch (Exception e) {
            throw new UnmarshallingException("Unable to read serialized authentication request");
        }
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
