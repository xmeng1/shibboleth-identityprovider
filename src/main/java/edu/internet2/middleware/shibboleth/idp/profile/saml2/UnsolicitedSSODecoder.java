/*
 * Licensed to the University Corporation for Advanced Internet Development, Inc.
 * under one or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.BaseSAML2MessageDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.profile.saml2.SSOProfileHandler.SSORequestContext;

/**
 * Shibboleth 2.x HTTP request parameter-based SSO authentication request message decoder.
 * 
 * <p>
 * This decoder understands and processes a set of defined HTTP request parameters representing a logical
 * SAML 2 SSO authentication request, and builds a corresponding {@link AuthnRequest} message.
 * This message is then stored in the {@link SAMLMessageContext} so that it may be processed 
 * by other components (e.g. profile handler) that process standard AuthnRequest messages.
 * </p>
 * .
 */
public class UnsolicitedSSODecoder extends BaseSAML2MessageDecoder implements SAMLMessageDecoder {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(UnsolicitedSSODecoder.class);

    /** The binding URI default value. */
    public String defaultBinding;
    
    /** AuthnRequest builder. */
    private SAMLObjectBuilder<AuthnRequest> authnRequestBuilder;

    /** Issuer builder. */
    private SAMLObjectBuilder<Issuer> issuerBuilder;

    /** NameIDPolicy builder. */
    private SAMLObjectBuilder<NameIDPolicy> nipBuilder;
    
    /** Identifier generator. */
    private IdentifierGenerator idGenerator;

    /**
     * Constructor.
     * 
     * @param identifierGenerator the IdentifierGenerator instance to use.
     */
    @SuppressWarnings("unchecked")
    public UnsolicitedSSODecoder(IdentifierGenerator identifierGenerator) {
        super();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        authnRequestBuilder = 
            (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        issuerBuilder = 
            (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        nipBuilder = 
            (SAMLObjectBuilder<NameIDPolicy>) builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);

        idGenerator = identifierGenerator;
        defaultBinding = SAMLConstants.SAML2_POST_BINDING_URI;
    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return "urn:mace:shibboleth:2.0:profiles:AuthnRequest";
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected boolean isIntendedDestinationEndpointURIRequired(SAMLMessageContext samlMsgCtx) {
        return false;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected String getIntendedDestinationEndpointURI(SAMLMessageContext samlMsgCtx) throws MessageDecodingException {
        // Not relevant in this binding/profile, there is neither SAML message
        // nor binding parameter with this information
        return null;
    }
    
    /**
     * Returns the default ACS binding.
     * @return  default binding URI
     */
    public String getDefaultBinding() {
        return defaultBinding;
    }
    
    /**
     * Sets the default ACS binding.
     * @param binding default binding URI
     */
    public void setDefaultBinding(String binding) {
        defaultBinding = binding;
    }
    
    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected void doDecode(MessageContext messageContext) throws MessageDecodingException {
        if (!(messageContext instanceof SSORequestContext)) {
            log.warn("Invalid message context type, this decoder only supports SSORequestContext");
            throw new MessageDecodingException(
                    "Invalid message context type, this decoder only supports SSORequestContext");
        }

        if (!(messageContext.getInboundMessageTransport() instanceof HTTPInTransport)) {
            log.warn("Invalid inbound message transport type, this decoder only support HTTPInTransport");
            throw new MessageDecodingException(
                    "Invalid inbound message transport type, this decoder only support HTTPInTransport");
        }

        SSORequestContext requestContext = (SSORequestContext) messageContext;
        HTTPInTransport transport = (HTTPInTransport) messageContext.getInboundMessageTransport();
        
        String providerId = DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("providerId"));
        if (providerId == null) {
            log.warn("No providerId parameter given in unsolicited SSO authentication request.");
            throw new MessageDecodingException(
                    "No providerId parameter given in unsolicited SSO authentication request.");
        }

        requestContext.setRelayState(DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("target")));

        String timeStr = DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("time"));
        String sessionID = ((HttpServletRequestAdapter) transport).getWrappedRequest().getRequestedSessionId();

        String binding = null;
        String acsURL = DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("shire"));
        if (acsURL == null) {
            acsURL = lookupACSURL(requestContext.getMetadataProvider(), providerId);
            if (acsURL == null) {
                log.warn("Unable to resolve SP ACS URL for AuthnRequest construction for entityID: {}",
                        providerId);
                throw new MessageDecodingException("Unable to resolve SP ACS URL for AuthnRequest construction");
            }
            binding = defaultBinding;
        }
        
        AuthnRequest authnRequest = buildAuthnRequest(providerId, acsURL, binding, timeStr, sessionID);
        requestContext.setInboundMessage(authnRequest);
        requestContext.setInboundSAMLMessage(authnRequest);
        log.debug("Mocked up SAML message");

        populateMessageContext(requestContext);
        
        requestContext.setUnsolicited(true);
    }

    /**
     * Build a SAML 2 AuthnRequest from the parameters specified in the inbound transport.
     * 
     * @param entityID the requester identity
     * @param acsURL the ACS URL
     * @param acsBinding the ACS binding URI
     * @param timeStr the request timestamp
     * @param sessionID the container session, if any
     * @return a newly constructed AuthnRequest instance
     */
    @SuppressWarnings("unchecked")
    private AuthnRequest buildAuthnRequest(String entityID, String acsURL, String acsBinding, String timeStr, String sessionID) {
        
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        authnRequest.setAssertionConsumerServiceURL(acsURL);
        if (acsBinding != null) {
            authnRequest.setProtocolBinding(acsBinding);
        }

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(entityID);
        authnRequest.setIssuer(issuer);

        // Matches the default semantic a typical SP would have.
        NameIDPolicy nip = nipBuilder.buildObject();
        nip.setAllowCreate(true);
        authnRequest.setNameIDPolicy(nip);
        
        if (timeStr != null) {
            authnRequest.setIssueInstant(
                    new DateTime(Long.parseLong(timeStr) * 1000, ISOChronology.getInstanceUTC()));
            if (sessionID != null) {
                // Construct a pseudo message ID by combining the timestamp
                // and a client-specific ID (the Java session ID).
                // This allows for replay detection if the 
                authnRequest.setID('_' + sessionID + '!' + timeStr);
            } else {
                authnRequest.setID(idGenerator.generateIdentifier());
            }
        } else {
            authnRequest.setID(idGenerator.generateIdentifier());
            authnRequest.setIssueInstant(new DateTime());
        }
        
        return authnRequest;
    }

    /**
     * Lookup the ACS URL for the specified SP entityID and binding URI.
     * 
     * @param mdProvider the SAML message context's metadata source
     * @param entityId the SP entityID
     * @return the resolved ACS URL endpoint
     * @throws MessageDecodingException if there is an error resolving the ACS URL
     */
    @SuppressWarnings("unchecked")
    private String lookupACSURL(MetadataProvider mdProvider, String entityId)
            throws MessageDecodingException {
        SPSSODescriptor spssoDesc = null;
        try {
            spssoDesc = (SPSSODescriptor) mdProvider.getRole(entityId, SPSSODescriptor.DEFAULT_ELEMENT_NAME,
                    SAMLConstants.SAML20P_NS);
        } catch (MetadataProviderException e) {
            throw new MessageDecodingException("Error resolving metadata role for SP entityId: " + entityId, e);
        }

        if (spssoDesc == null) {
            throw new MessageDecodingException(
                    "SAML 2 SPSSODescriptor could not be resolved from metadata for SP entityID: " + entityId);
        }

        BasicEndpointSelector selector = new BasicEndpointSelector();
        selector.setEntityRoleMetadata(spssoDesc);
        selector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        selector.getSupportedIssuerBindings().add(defaultBinding);

        Endpoint endpoint = selector.selectEndpoint();
        if (endpoint == null || endpoint.getLocation() == null) {
            throw new MessageDecodingException(
                    "SAML 2 ACS endpoint could not be resolved from metadata for SP entityID and binding: " + entityId
                            + " -- " + defaultBinding);
        }

        return endpoint.getLocation();
    }

}