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

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AttributeQueryConfiguration;

/**
 * SAML 1 Attribute Query profile handler.
 */
public class AttributeQueryProfileHandler extends AbstractSAML1ProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AttributeQueryProfileHandler.class);

    /** Builder of assertion consumer service endpoints. */
    private SAMLObjectBuilder<AssertionConsumerService> acsEndpointBuilder;

    /** Constructor. */
    public AttributeQueryProfileHandler() {
        super();

        acsEndpointBuilder = (SAMLObjectBuilder<AssertionConsumerService>) getBuilderFactory().getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml1:query:attribute";
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        AttributeQueryContext requestContext = decodeRequest(inTransport, outTransport);

        Response samlResponse;
        try {
            if (requestContext.getProfileConfiguration() == null) {
                log.error("SAML 1 Attribute Query profile is not configured for relying party "
                        + requestContext.getInboundMessageIssuer());
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                        "SAML 1 Attribute Query profile is not configured for relying party "
                                + requestContext.getInboundMessageIssuer()));
                samlResponse = buildErrorResponse(requestContext);
            } else {
                resolvePrincipal(requestContext);
                resolveAttributes(requestContext);
                requestContext.setReleasedAttributes(requestContext.getPrincipalAttributes().keySet());

                ArrayList<Statement> statements = new ArrayList<Statement>();
                AttributeStatement attributeStatement = buildAttributeStatement(requestContext,
                        "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches");
                if (attributeStatement != null) {
                    statements.add(attributeStatement);
                }

                samlResponse = buildResponse(requestContext, statements);
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
        log.debug("Decoding message with decoder binding {}", getInboundBinding());

        MetadataProvider metadataProvider = getMetadataProvider();

        AttributeQueryContext requestContext = new AttributeQueryContext();
        requestContext.setMetadataProvider(metadataProvider);
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());

        requestContext.setCommunicationProfileId(AttributeQueryConfiguration.PROFILE_ID);
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML11P_NS);
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        try {
            SAMLMessageDecoder decoder = getMessageDecoders().get(getInboundBinding());
            if (decoder == null) {
                throw new ProfileException("No message decoder configured for inbound binding " + getInboundBinding());
            }
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded request");

            Request request = requestContext.getInboundSAMLMessage();
            if (request == null || !(request instanceof Request) || request.getAttributeQuery() == null) {
                log.error("Incoming message was not an Attribute request");
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER, null,
                        "Invalid SAML Attribute Request message."));
                throw new ProfileException("Invalid SAML Attribute Request message.");
            }

            return requestContext;
        } catch (MessageDecodingException e) {
            log.error("Error decoding attribute query message", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error decoding message"));
            throw new ProfileException("Error decoding attribute query message");
        } catch (SecurityException e) {
            log.error("Message did not meet security requirements", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Message did not meet security requirements"));
            throw new ProfileException("Message did not meet security policy requirements", e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            Request request = requestContext.getInboundSAMLMessage();
            if (request == null) {
                log.error("Decoder did not contain an attribute query, an error occured decoding the message");
                throw new ProfileException("Unable to decode message.");
            }
            AttributeQuery query = request.getAttributeQuery();
            if (query != null) {
                requestContext.setSubjectNameIdentifier(query.getSubject().getNameIdentifier());
            }

            String relyingPartyId = requestContext.getInboundMessageIssuer();
            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
            if (rpConfig == null) {
                log.error("Unable to retrieve relying party configuration data for entity with ID {}", relyingPartyId);
                throw new ProfileException("Unable to retrieve relying party configuration data for entity with ID "
                        + relyingPartyId);
            }
            requestContext.setRelyingPartyConfiguration(rpConfig);

            AttributeQueryConfiguration profileConfig = (AttributeQueryConfiguration) rpConfig
                    .getProfileConfiguration(AttributeQueryConfiguration.PROFILE_ID);
            if (profileConfig != null) {
                requestContext.setProfileConfiguration(profileConfig);
                requestContext.setOutboundMessageArtifactType(profileConfig.getOutboundArtifactType());
                if (profileConfig.getSigningCredential() != null) {
                    requestContext.setOutboundSAMLMessageSigningCredential(profileConfig.getSigningCredential());
                } else if (rpConfig.getDefaultSigningCredential() != null) {
                    requestContext.setOutboundSAMLMessageSigningCredential(rpConfig.getDefaultSigningCredential());
                }
            }
            requestContext.setPeerEntityEndpoint(selectEndpoint(requestContext));

            String assertingPartyId = requestContext.getRelyingPartyConfiguration().getProviderId();
            requestContext.setLocalEntityId(assertingPartyId);
            try {
                EntityDescriptor localEntityDescriptor = metadataProvider.getEntityDescriptor(assertingPartyId);
                if (localEntityDescriptor != null) {
                    requestContext.setLocalEntityMetadata(localEntityDescriptor);
                    requestContext.setLocalEntityRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
                    requestContext.setLocalEntityRoleMetadata(localEntityDescriptor
                            .getAttributeAuthorityDescriptor(SAMLConstants.SAML11P_NS));
                }
            } catch (MetadataProviderException e) {
                log.error("Unable to locate metadata for asserting party");
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                        "Error locating asserting party metadata"));
                throw new ProfileException("Error locating asserting party metadata");
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

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryContext extends
            BaseSAML1ProfileRequestContext<Request, Response, AttributeQueryConfiguration> {}
}