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

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.SAML2ArtifactMessageContext;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.ArtifactResolutionConfiguration;

/**
 * SAML 2.0 Artifact resolution profile handler.
 */
public class ArtifactResolution extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ArtifactResolution.class);

    /** Map artifacts to SAML messages. */
    private SAMLArtifactMap artifactMap;

    /** Artifact response object builder. */
    private SAMLObjectBuilder<ArtifactResponse> responseBuilder;

    /** Builder of assertion consumer service endpoints. */
    private SAMLObjectBuilder<AssertionConsumerService> acsEndpointBuilder;

    /**
     * Constructor.
     * 
     * @param map ArtifactMap used to lookup artifacts to be resolved.
     */
    public ArtifactResolution(SAMLArtifactMap map) {
        super();

        artifactMap = map;

        responseBuilder = (SAMLObjectBuilder<ArtifactResponse>) getBuilderFactory().getBuilder(
                ArtifactResponse.DEFAULT_ELEMENT_NAME);
        acsEndpointBuilder = (SAMLObjectBuilder<AssertionConsumerService>) getBuilderFactory().getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return ArtifactResolutionConfiguration.PROFILE_ID;
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        ArtifactResponse samlResponse;

        ArtifactResolutionRequestContext requestContext = decodeRequest(inTransport, outTransport);

        try {
            if (requestContext.getProfileConfiguration() == null) {
                log.error("SAML 2 Artifact Resolve profile is not configured for relying party "
                        + requestContext.getInboundMessageIssuer());
                requestContext.setFailureStatus(buildStatus(StatusCode.SUCCESS_URI, StatusCode.REQUEST_DENIED_URI,
                        "SAML 2 Artifact Resolve profile is not configured for relying party "
                                + requestContext.getInboundMessageIssuer()));
                throw new ProfileException("SAML 2 Artifact Resolve profile is not configured for relying party "
                        + requestContext.getInboundMessageIssuer());
            }

            checkSamlVersion(requestContext);

            SAMLArtifactMapEntry artifactEntry = artifactMap.get(requestContext.getArtifact());
            if (artifactEntry == null || artifactEntry.isExpired()) {
                log.error("Unknown artifact.");
                requestContext.setFailureStatus(buildStatus(StatusCode.SUCCESS_URI, StatusCode.REQUEST_DENIED_URI,
                        "Unknown artifact."));
            }

            if (!artifactEntry.getIssuerId().equals(requestContext.getLocalEntityId())) {
                log.error("Artifact issuer mismatch.  Artifact issued by " + artifactEntry.getIssuerId()
                        + " but IdP has entity ID of " + requestContext.getLocalEntityId());
                requestContext.setFailureStatus(buildStatus(StatusCode.SUCCESS_URI, StatusCode.REQUEST_DENIED_URI,
                        "Artifact issuer mismatch."));
            }

            if (!artifactEntry.getRelyingPartyId().equals(requestContext.getInboundMessageIssuer())) {
                log.error("Artifact requester mismatch.  Artifact was issued to " + artifactEntry.getRelyingPartyId()
                        + " but was resolve request came from " + requestContext.getInboundMessageIssuer());
                requestContext.setFailureStatus(buildStatus(StatusCode.SUCCESS_URI, StatusCode.REQUEST_DENIED_URI,
                        "Artifact requester mismatch."));
            }

            // create the SAML response
            requestContext.setReferencedMessage(artifactEntry.getSamlMessage());
            samlResponse = buildArtifactResponse(requestContext);
        } catch (ProfileException e) {
            samlResponse = buildArtifactErrorResponse(requestContext);
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());

        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Decodes an incoming request and populates a created request context with the resultant information.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @return the created request context
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected ArtifactResolutionRequestContext decodeRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        log.debug("Decoding message with decoder binding {}", getInboundBinding());

        ArtifactResolutionRequestContext requestContext = new ArtifactResolutionRequestContext();
        requestContext.setCommunicationProfileId(getProfileId());

        MetadataProvider metadataProvider = getMetadataProvider();
        requestContext.setMetadataProvider(metadataProvider);

        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        try {
            SAMLMessageDecoder decoder = getMessageDecoders().get(getInboundBinding());
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded request");
            return requestContext;
        } catch (MessageDecodingException e) {
            log.error("Error decoding artifact resolve message", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Error decoding message"));
            throw new ProfileException("Error decoding artifact resolve message");
        } catch (SecurityException e) {
            log.error("Message did not meet security requirements", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI,
                    "Message did not meet security requirements"));
            throw new ProfileException("Message did not meet security requirements", e);
        } finally {
            populateRequestContext(requestContext);
        }
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
            requestContext.setLocalEntityRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setLocalEntityRoleMetadata(localEntityDescriptor
                    .getAttributeAuthorityDescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    /**
     * Populates the request context with information from the inbound SAML message.
     * 
     * This method requires the the following request context properties to be populated: inbound saml message
     * 
     * This methods populates the following request context properties: subject name identifier
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the inbound SAML message or subject identifier is null
     */
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        ArtifactResolve samlMessage = (ArtifactResolve) requestContext.getInboundSAMLMessage();
        ((ArtifactResolutionRequestContext) requestContext).setArtifact(samlMessage.getArtifact().getArtifact());
    }

    /**
     * Selects the appropriate endpoint for the relying party and stores it in the request context.
     * 
     * @param requestContext current request context
     * 
     * @return Endpoint selected from the information provided in the request context
     */
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) {
        Endpoint endpoint;

        if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
            endpoint = acsEndpointBuilder.buildObject();
            endpoint.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        } else {
            BasicEndpointSelector endpointSelector = new BasicEndpointSelector();
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
     * Constructs a artifact resolution response with the derferenced SAML message inside.
     * 
     * @param requestContext current request context
     * 
     * @return constructed response
     */
    protected ArtifactResponse buildArtifactResponse(ArtifactResolutionRequestContext requestContext) {
        DateTime issueInstant = new DateTime();

        // create the SAML response and add the assertion
        ArtifactResponse samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(issueInstant);
        populateStatusResponse(requestContext, samlResponse);

        if (requestContext.getFailureStatus() == null) {
            Status status = buildStatus(StatusCode.SUCCESS_URI, null, null);
            samlResponse.setStatus(status);
            samlResponse.setMessage(requestContext.getReferencedMessage());
        } else {
            samlResponse.setStatus(requestContext.getFailureStatus());
        }

        return samlResponse;
    }

    /**
     * Constructs an artifact resolution response with an error status as content.
     * 
     * @param requestContext current request context
     * 
     * @return constructed response
     */
    protected ArtifactResponse buildArtifactErrorResponse(ArtifactResolutionRequestContext requestContext) {
        ArtifactResponse samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(new DateTime());
        populateStatusResponse(requestContext, samlResponse);

        samlResponse.setStatus(requestContext.getFailureStatus());

        return samlResponse;
    }

    /** Represents the internal state of a SAML 2.0 Artiface resolver request while it's being processed by the IdP. */
    public class ArtifactResolutionRequestContext extends
            BaseSAML2ProfileRequestContext<ArtifactResolve, ArtifactResponse, ArtifactResolutionConfiguration>
            implements SAML2ArtifactMessageContext<ArtifactResolve, ArtifactResponse, NameID> {

        /** Artifact to be resolved. */
        private String artifact;

        /** Message referenced by the SAML artifact. */
        private SAMLObject referencedMessage;

        /** {@inheritDoc} */
        public String getArtifact() {
            return artifact;
        }

        /** {@inheritDoc} */
        public void setArtifact(String saml2Artifact) {
            this.artifact = saml2Artifact;
        }

        /** {@inheritDoc} */
        public SAMLObject getReferencedMessage() {
            return referencedMessage;
        }

        /** {@inheritDoc} */
        public void setReferencedMessage(SAMLObject message) {
            referencedMessage = message;
        }
    }
}