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

import org.apache.log4j.Logger;
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
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.ArtifactResolutionConfiguration;

/**
 * SAML 2.0 Artifact resolution profile handler.
 */
public class ArtifactResolution extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(ArtifactResolution.class);

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
        return "urn:mace:shibboleth:2.0:idp:profiles:saml2:request:artifact";
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
            artifactMap.remove(requestContext.getArtifact());
            SAMLObject referencedMessage = artifactEntry.getSamlMessage();
            requestContext.setReferencedMessage(referencedMessage);

            // create the SAML response
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
        if (log.isDebugEnabled()) {
            log.debug("Decoding incomming request");
        }

        MetadataProvider metadataProvider = getMetadataProvider();

        ArtifactResolutionRequestContext requestContext = new ArtifactResolutionRequestContext();
        requestContext.setMetadataProvider(metadataProvider);
        
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        
        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        try {
            SAMLMessageDecoder decoder = getMessageDecoders().get(getInboundBinding());
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            if (log.isDebugEnabled()) {
                log.debug("Decoded request");
            }
            return requestContext;
        } catch (MessageDecodingException e) {
            log.error("Error decoding artifact resolve message", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Error decoding message"));
            throw new ProfileException("Error decoding artifact resolve message");
        } catch (SecurityPolicyException e) {
            log.error("Message did not meet security policy requirements", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI,
                    "Message did not meet security policy requirements"));
            throw new ProfileException("Message did not meet security policy requirements", e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            try {
                requestContext.setArtifact(requestContext.getInboundSAMLMessage().getArtifact().getArtifact());
                
                String relyingPartyId = requestContext.getInboundMessageIssuer();
                RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
                requestContext.setRelyingPartyConfiguration(rpConfig);
                requestContext.setPeerEntityEndpoint(selectEndpoint(requestContext));

                String assertingPartyId = requestContext.getRelyingPartyConfiguration().getProviderId();
                requestContext.setLocalEntityId(assertingPartyId);
                requestContext.setLocalEntityMetadata(metadataProvider.getEntityDescriptor(assertingPartyId));
                requestContext.setLocalEntityRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setLocalEntityRoleMetadata(requestContext.getLocalEntityMetadata()
                        .getAttributeAuthorityDescriptor(SAMLConstants.SAML20P_NS));

                ArtifactResolutionConfiguration profileConfig = (ArtifactResolutionConfiguration) rpConfig
                        .getProfileConfiguration(ArtifactResolutionConfiguration.PROFILE_ID);
                if(profileConfig != null){
                    requestContext.setProfileConfiguration(profileConfig);
                    if (profileConfig.getSigningCredential() != null) {
                        requestContext.setOutboundSAMLMessageSigningCredential(profileConfig.getSigningCredential());
                    } else if (rpConfig.getDefaultSigningCredential() != null) {
                        requestContext.setOutboundSAMLMessageSigningCredential(rpConfig.getDefaultSigningCredential());
                    }
                }

            } catch (MetadataProviderException e) {
                log.error("Unable to locate metadata for asserting or relying party");
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                        "Error locating party metadata"));
                throw new ProfileException("Error locating party metadata");
            }
        }
    }

    /**
     * Selects the appropriate endpoint for the relying party and stores it in the request context.
     * 
     * @param requestContext current request context
     * 
     * @return Endpoint selected from the information provided in the request context
     */
    protected Endpoint selectEndpoint(ArtifactResolutionRequestContext requestContext) {
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

        /**
         * Gets the SAML message referenced by the artifact.
         * 
         * @return SAML message referenced by the artifact
         */
        public SAMLObject getReferencedMessage() {
            return referencedMessage;
        }

        /**
         * Sets the SAML message referenced by the artifact.
         * 
         * @param message SAML message referenced by the artifact
         */
        public void setReferencedMessage(SAMLObject message) {
            referencedMessage = message;
        }
    }
}