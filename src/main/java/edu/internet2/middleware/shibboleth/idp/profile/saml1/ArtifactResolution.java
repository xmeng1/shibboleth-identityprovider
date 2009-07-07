/*
 * Copyright 2006 University Corporation for Advanced Internet Development, Inc.
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
import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.binding.SAML1ArtifactMessageContext;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AssertionArtifact;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
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
import org.slf4j.helpers.MessageFormatter;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.ArtifactResolutionConfiguration;

/** SAML 1 Artifact resolution profile handler. */
public class ArtifactResolution extends AbstractSAML1ProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ArtifactResolution.class);

    /** Builder of Response objects. */
    private SAMLObjectBuilder<Response> responseBuilder;

    /** Builder of assertion consumer service endpoints. */
    private SAMLObjectBuilder<AssertionConsumerService> acsEndpointBuilder;

    /** Map artifacts to SAML messages. */
    private SAMLArtifactMap artifactMap;

    /**
     * Constructor.
     * 
     * @param map ArtifactMap used to lookup artifacts to be resolved.
     */
    public ArtifactResolution(SAMLArtifactMap map) {
        super();

        artifactMap = map;

        responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        acsEndpointBuilder = (SAMLObjectBuilder<AssertionConsumerService>) getBuilderFactory().getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return ArtifactResolutionConfiguration.PROFILE_ID;
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        Response samlResponse;

        ArtifactResolutionRequestContext requestContext = new ArtifactResolutionRequestContext();
        decodeRequest(requestContext, inTransport, outTransport);

        try {
            if (requestContext.getProfileConfiguration() == null) {
                String msg = MessageFormatter.format(
                        "SAML 1 Artifact resolution profile is not configured for relying party '{}'", requestContext
                                .getInboundMessageIssuer());
                requestContext.setFailureStatus(buildStatus(StatusCode.SUCCESS, StatusCode.REQUEST_DENIED, msg));
                log.warn(msg);
                throw new ProfileException(msg);
            }

            checkSamlVersion(requestContext);

            derferenceArtifacts(requestContext);

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
     * @param requestContext request context to which decoded information should be added
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected void decodeRequest(ArtifactResolutionRequestContext requestContext, HTTPInTransport inTransport,
            HTTPOutTransport outTransport) throws ProfileException {
        log.debug("Decoding message with decoder binding '{}'", getInboundBinding());

        requestContext.setCommunicationProfileId(getProfileId());

        MetadataProvider metadataProvider = getMetadataProvider();
        requestContext.setMetadataProvider(metadataProvider);

        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML11P_NS);
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        try {
            SAMLMessageDecoder decoder = getMessageDecoders().get(getInboundBinding());
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded artifact resolution request from relying party '{}'", requestContext
                    .getInboundMessageIssuer());
        } catch (MessageDecodingException e) {
            String msg = "Error decoding artifact resolve message";
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, msg));
            log.warn(msg, e);
            throw new ProfileException(msg, e);
        } catch (SecurityException e) {
            String msg = "Message did not meet security requirements";
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED, msg));
            log.warn(msg, e);
            throw new ProfileException(msg, e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
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
            requestContext.setPeerEntityRoleMetadata(relyingPartyMetadata.getSPSSODescriptor(SAMLConstants.SAML11P_NS));
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
                    .getAttributeAuthorityDescriptor(SAMLConstants.SAML11P_NS));
        }
    }

    /** {@inheritDoc} */
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        // nothing to do here
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

        if (getInboundBinding().equals(SAMLConstants.SAML1_SOAP11_BINDING_URI)) {
            endpoint = acsEndpointBuilder.buildObject();
            endpoint.setBinding(SAMLConstants.SAML1_SOAP11_BINDING_URI);
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
     * Dereferences the artifacts within the incoming request and stores them in the request context.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the incoming request does not contain any {@link AssertionArtifact}s.
     */
    protected void derferenceArtifacts(ArtifactResolutionRequestContext requestContext) throws ProfileException {
        Request request = requestContext.getInboundSAMLMessage();
        List<AssertionArtifact> assertionArtifacts = request.getAssertionArtifacts();

        if (assertionArtifacts == null || assertionArtifacts.size() == 0) {
            String msg = MessageFormatter.format("No AssertionArtifacts available in request from relying party '{}'",
                    requestContext.getInboundMessageIssuer());
            log.warn(msg);
            throw new ProfileException(msg);
        }

        ArrayList<Assertion> assertions = new ArrayList<Assertion>();
        SAMLArtifactMapEntry artifactEntry;
        for (AssertionArtifact assertionArtifact : assertionArtifacts) {
            artifactEntry = artifactMap.get(assertionArtifact.getAssertionArtifact());
            if (artifactEntry == null || artifactEntry.isExpired()) {
                log.warn("Unknown AssertionArtifact '{}' from relying party '{}'", assertionArtifact
                        .getAssertionArtifact(), requestContext.getInboundMessageIssuer());
                continue;
            }

            if (!artifactEntry.getIssuerId().equals(requestContext.getLocalEntityId())) {
                log.warn("Artifact issuer mismatch.  Artifact issued by '{}' but IdP has entity ID of '{}'",
                        artifactEntry.getIssuerId(), requestContext.getLocalEntityId());
                continue;
            }

            artifactMap.remove(assertionArtifact.getAssertionArtifact());
            assertions.add((Assertion) artifactEntry.getSamlMessage());
        }

        requestContext.setDereferencedAssertions(assertions);
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

        if (requestContext.getDereferencedAssertions() != null) {
            samlResponse.getAssertions().addAll(requestContext.getDereferencedAssertions());
        }

        Status status = buildStatus(StatusCode.SUCCESS, null, null);
        samlResponse.setStatus(status);

        return samlResponse;
    }

    /** Represents the internal state of a SAML 1 Artifact resolver request while it's being processed by the IdP. */
    public class ArtifactResolutionRequestContext extends
            BaseSAML1ProfileRequestContext<Request, Response, ArtifactResolutionConfiguration> implements
            SAML1ArtifactMessageContext<Request, Response, NameIdentifier> {

        /** Artifact to be resolved. */
        private Collection<String> artifacts;

        /** Message referenced by the SAML artifact. */
        private Collection<Assertion> referencedAssertions;

        /** {@inheritDoc} */
        public Collection<String> getArtifacts() {
            return artifacts;
        }

        /** {@inheritDoc} */
        public void setArtifacts(Collection<String> encodedArtifacts) {
            this.artifacts = encodedArtifacts;
        }

        /**
         * Gets the SAML assertions referenced by the artifact(s).
         * 
         * @return SAML assertions referenced by the artifact(s)
         */
        public Collection<Assertion> getDereferencedAssertions() {
            return referencedAssertions;
        }

        /**
         * Sets the SAML assertions referenced by the artifact(s).
         * 
         * @param assertions SAML assertions referenced by the artifact(s)
         */
        public void setDereferencedAssertions(Collection<Assertion> assertions) {
            referencedAssertions = assertions;
        }
    }
}