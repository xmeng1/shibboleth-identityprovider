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

import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.binding.SAML1ArtifactMessageContext;
import org.opensaml.saml1.binding.artifact.AbstractSAML1Artifact;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
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
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.ArtifactResolutionConfiguration;

/**
 * SAML 2.0 Artifact resolution profile handler.
 */
public class ArtifactResolution extends AbstractSAML1ProfileHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(ArtifactResolution.class);

    /** Builder of Response objects. */
    private SAMLObjectBuilder<Response> responseBuilder;

    /** Map artifacts to SAML messages. */
    private SAMLArtifactMap artifactMap;

    /** Constructor. */
    public ArtifactResolution() {
        super();
        responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml1:request:artifact";
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        Response samlResponse;

        ArtifactResolutionRequestContext requestContext = decodeRequest(inTransport, outTransport);

        try {
            if (requestContext.getRelyingPartyConfiguration() == null) {
                log.error("SAML 1 Artifact resolution profile is not configured for relying party "
                        + requestContext.getPeerEntityId());
                requestContext.setFailureStatus(buildStatus(StatusCode.SUCCESS, StatusCode.REQUEST_DENIED,
                        "SAML 1 Artifact resolution profile is not configured for relying party "
                                + requestContext.getPeerEntityId()));
                throw new ProfileException("SAML 1 Artifact resolution profile is not configured for relying party "
                        + requestContext.getPeerEntityId());
            }

            checkSamlVersion(requestContext);

            // create the SAML response
            samlResponse = buildArtifactResponse(requestContext);
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
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setMetadataProvider(metadataProvider);

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
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error decoding message"));
            throw new ProfileException("Error decoding artifact resolve message");
        } catch (SecurityPolicyException e) {
            log.error("Message did not meet security policy requirements", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Message did not meet security policy requirements"));
            throw new ProfileException("Message did not meet security policy requirements", e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            try {
                Request samlRequest = requestContext.getInboundSAMLMessage();
                requestContext.setInboundSAMLMessageId(samlRequest.getID());
                requestContext.setInboundSAMLMessageIssueInstant(samlRequest.getIssueInstant());

                String relyingPartyId = requestContext.getPeerEntityId();
                requestContext.setPeerEntityMetadata(metadataProvider.getEntityDescriptor(relyingPartyId));
                requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setPeerEntityRoleMetadata(requestContext.getPeerEntityMetadata().getSPSSODescriptor(
                        SAMLConstants.SAML11P_NS));
                RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
                requestContext.setRelyingPartyConfiguration(rpConfig);

                String assertingPartyId = requestContext.getRelyingPartyConfiguration().getProviderId();
                requestContext.setLocalEntityId(assertingPartyId);
                requestContext.setLocalEntityMetadata(metadataProvider.getEntityDescriptor(assertingPartyId));
                requestContext.setLocalEntityRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setLocalEntityRoleMetadata(requestContext.getLocalEntityMetadata()
                        .getAttributeAuthorityDescriptor(SAMLConstants.SAML11P_NS));

                ArtifactResolutionConfiguration profileConfig = (ArtifactResolutionConfiguration) rpConfig
                        .getProfileConfiguration(ArtifactResolutionConfiguration.PROFILE_ID);
                requestContext.setProfileConfiguration(profileConfig);
                if (profileConfig.getSigningCredential() != null) {
                    requestContext.setOutboundSAMLMessageSigningCredential(profileConfig.getSigningCredential());
                } else if (rpConfig.getDefaultSigningCredential() != null) {
                    requestContext.setOutboundSAMLMessageSigningCredential(rpConfig.getDefaultSigningCredential());
                }

            } catch (MetadataProviderException e) {
                log.error("Unable to locate metadata for asserting or relying party");
                requestContext
                        .setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error locating party metadata"));
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
        BasicEndpointSelector endpointSelector = new BasicEndpointSelector();
        endpointSelector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        endpointSelector.setMetadataProvider(getMetadataProvider());
        endpointSelector.setEntityMetadata(requestContext.getPeerEntityMetadata());
        endpointSelector.setEntityRoleMetadata(requestContext.getPeerEntityRoleMetadata());
        endpointSelector.setSamlRequest(requestContext.getInboundSAMLMessage());
        endpointSelector.getSupportedIssuerBindings().addAll(getSupportedOutboundBindings());
        return endpointSelector.selectEndpoint();
    }

    /**
     * Derferences the provided artifacts and stores them in the request context.
     * 
     * @param requestContext current request context
     */
    protected void derferenceArtifacts(ArtifactResolutionRequestContext requestContext) {
        Collection<AbstractSAML1Artifact> artifacts = requestContext.getArtifacts();
        if (artifacts != null) {
            ArrayList<Assertion> assertions = new ArrayList<Assertion>();
            SAMLArtifactMapEntry artifactEntry;

            for (AbstractSAML1Artifact artifact : artifacts) {
                artifactEntry = artifactMap.get(artifact.getArtifactBytes());
                if (artifactEntry == null || artifactEntry.isExpired()) {
                    log.error("Unknown artifact.");
                }

                if (!artifactEntry.getIssuerId().equals(requestContext.getLocalEntityId())) {
                    log.error("Artifact issuer mismatch.  Artifact issued by " + artifactEntry.getIssuerId()
                            + " but IdP has entity ID of " + requestContext.getLocalEntityId());
                }

                if (!artifactEntry.getRelyingPartyId().equals(requestContext.getPeerEntityId())) {
                    log.error("Artifact requester mismatch.  Artifact was issued to "
                            + artifactEntry.getRelyingPartyId() + " but was resolve request came from "
                            + requestContext.getPeerEntityId());
                }
                artifactMap.remove(artifact.getArtifactBytes());
                assertions.add((Assertion) artifactEntry.getSamlMessage());
            }
            requestContext.setReferencedAssertions(assertions);
        }
    }

    /**
     * Builds the response to the artifact request.
     * 
     * @param requestContext current request context
     * 
     * @return response to the artifact request
     */
    protected Response buildArtifactResponse(ArtifactResolutionRequestContext requestContext) {
        DateTime issueInstant = new DateTime();

        // create the SAML response and add the assertion
        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(issueInstant);
        populateStatusResponse(requestContext, samlResponse);

        if (requestContext.getReferencedAssertions() != null) {
            samlResponse.getAssertions().addAll(requestContext.getReferencedAssertions());
        }

        Status status = buildStatus(StatusCode.SUCCESS, null, null);
        samlResponse.setStatus(status);

        return samlResponse;
    }

    /** Represents the internal state of a SAML 1 Artiface resolver request while it's being processed by the IdP. */
    public class ArtifactResolutionRequestContext extends
            BaseSAML1ProfileRequestContext<Request, Response, ArtifactResolutionConfiguration> implements
            SAML1ArtifactMessageContext<Request, Response, NameIdentifier> {

        /** Artifact to be resolved. */
        private Collection<AbstractSAML1Artifact> artifacts;

        /** Message referenced by the SAML artifact. */
        private Collection<Assertion> referencedAssertions;

        /**
         * Gets the artifacts to be resolved.
         * 
         * @return artifacts to be resolved
         */
        public Collection<AbstractSAML1Artifact> getArtifacts() {
            return artifacts;
        }

        /**
         * Sets the artifacts to be resolved.
         * 
         * @param artifacts artifacts to be resolved
         */
        public void setArtifacts(Collection<AbstractSAML1Artifact> artifacts) {
            this.artifacts = artifacts;
        }

        /**
         * Gets the SAML assertions referenced by the artifact(s).
         * 
         * @return SAML assertions referenced by the artifact(s)
         */
        public Collection<Assertion> getReferencedAssertions() {
            return referencedAssertions;
        }

        /**
         * Sets the SAML assertions referenced by the artifact(s).
         * 
         * @param assertions SAML assertions referenced by the artifact(s)
         */
        public void setReferencedAssertions(Collection<Assertion> assertions) {
            referencedAssertions = assertions;
        }
    }
}