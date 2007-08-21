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

import org.apache.log4j.Logger;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
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
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AttributeQueryConfiguration;

/**
 * SAML 1 Attribute Query profile handler.
 */
public class AttributeQueryProfileHandler extends AbstractSAML1ProfileHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(AttributeQueryProfileHandler.class);

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml1:query:attribute";
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        AttributeQueryContext requestContext = decodeRequest(inTransport, outTransport);

        Response samlResponse;
        try {
            if (requestContext.getRelyingPartyConfiguration() == null) {
                log.error("SAML 1 Attribute Query profile is not configured for relying party "
                        + requestContext.getPeerEntityId());
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                        "SAML 1 Attribute Query profile is not configured for relying party "
                                + requestContext.getPeerEntityId()));
                samlResponse = buildErrorResponse(requestContext);
            }

            resolvePrincipal(requestContext);
            resolveAttributes(requestContext);
            requestContext.setReleasedAttributes(requestContext.getPrincipalAttributes().keySet());
            
            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAttributeStatement(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"));

            samlResponse = buildResponse(requestContext, statements);
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
    protected AttributeQueryContext decodeRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Decoding incomming request");
        }

        MetadataProvider metadataProvider = getMetadataProvider();

        AttributeQueryContext requestContext = new AttributeQueryContext();
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML11P_NS);
        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML11P_NS);
        requestContext.setMetadataProvider(metadataProvider);

        try {
            SAMLMessageDecoder decoder = getMessageDecoders().get(getInboundBinding());
            if (decoder == null) {
                throw new ProfileException("No message decoder configured for inbound binding " + getInboundBinding());
            }
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            if (log.isDebugEnabled()) {
                log.debug("Decoded request");
            }
            return requestContext;
        } catch (MessageDecodingException e) {
            log.error("Error decoding attribute query message", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error decoding message"));
            throw new ProfileException("Error decoding attribute query message");
        } catch (SecurityPolicyException e) {
            log.error("Message did not meet security policy requirements", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Message did not meet security policy requirements"));
            throw new ProfileException("Message did not meet security policy requirements", e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            try {
                Request attributeRequest = requestContext.getInboundSAMLMessage();
                requestContext.setInboundSAMLMessageId(attributeRequest.getID());
                requestContext.setInboundSAMLMessageIssueInstant(attributeRequest.getIssueInstant());

                String relyingPartyId = requestContext.getPeerEntityId();
                requestContext.setPeerEntityMetadata(metadataProvider.getEntityDescriptor(relyingPartyId));
                requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setPeerEntityRoleMetadata(requestContext.getPeerEntityMetadata().getSPSSODescriptor(
                        SAMLConstants.SAML10P_NS));
                RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
                requestContext.setRelyingPartyConfiguration(rpConfig);
                requestContext.setPeerEntityEndpoint(selectEndpoint(requestContext));

                String assertingPartyId = requestContext.getRelyingPartyConfiguration().getProviderId();
                requestContext.setLocalEntityId(assertingPartyId);
                requestContext.setLocalEntityMetadata(metadataProvider.getEntityDescriptor(assertingPartyId));
                requestContext.setLocalEntityRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setLocalEntityRoleMetadata(requestContext.getLocalEntityMetadata()
                        .getAttributeAuthorityDescriptor(SAMLConstants.SAML10P_NS));

                AttributeQueryConfiguration profileConfig = (AttributeQueryConfiguration) rpConfig
                        .getProfileConfiguration(AttributeQueryConfiguration.PROFILE_ID);
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
    protected Endpoint selectEndpoint(AttributeQueryContext requestContext) {
        BasicEndpointSelector endpointSelector = new BasicEndpointSelector();
        endpointSelector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        endpointSelector.setMetadataProvider(getMetadataProvider());
        endpointSelector.setEntityMetadata(requestContext.getPeerEntityMetadata());
        endpointSelector.setEntityRoleMetadata(requestContext.getPeerEntityRoleMetadata());
        endpointSelector.setSamlRequest(requestContext.getInboundSAMLMessage());
        endpointSelector.getSupportedIssuerBindings().addAll(getSupportedOutboundBindings());

        return endpointSelector.selectEndpoint();
    }

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryContext extends
            BaseSAML1ProfileRequestContext<Request, Response, AttributeQueryConfiguration> {

        /** Current attribute query. */
        private AttributeQuery attributeQuery;

        /**
         * Gets the attribute query of the request.
         * 
         * @return attribute query of the request
         */
        public AttributeQuery getAttributeQuery() {
            return attributeQuery;
        }

        /**
         * Sets the attribute query of the request.
         * 
         * @param query attribute query of the request
         */
        public void setAttributeQuery(AttributeQuery query) {
            attributeQuery = query;
        }
    }
}