/*
 *  Copyright 2009 NIIF Institute.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.LogoutRequestConfiguration;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.MessageFormatter;

/**
 *
 */
public class SLOProfileHandler extends AbstractSAML2ProfileHandler {

    private static final Logger log =
            LoggerFactory.getLogger(SLOProfileHandler.class);

    public SLOProfileHandler() {
        super();
        log.info("SLOProfileHandler Init");
    }

    @Override
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        LogoutRequest request =
                (LogoutRequest) requestContext.getInboundSAMLMessage();
        if (request != null) {
            request.getSessionIndexes(); //TODO...
        }
    }

    @Override
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        Endpoint endpoint = null;

        /* TODO
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
         */

        return endpoint;
    }

    @Override
    public String getProfileId() {
        return LogoutRequestConfiguration.PROFILE_ID;
    }

    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        LogoutResponse samlResponse = null;

        LogoutRequestContext requestContext = new LogoutRequestContext();

        try {
            decodeRequest(requestContext, inTransport, outTransport);

            if (requestContext.getProfileConfiguration() == null) {
                String msg =
                        MessageFormatter.format(
                        "SAML 2 Single Logout profile is not configured for relying party '{}'",
                        requestContext.getInboundMessage());
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI,
                        StatusCode.REQUEST_DENIED_URI, msg));
                log.warn(msg);
            } else {
                checkSamlVersion(requestContext);

            }
        } catch (ProfileException e) {
            //samlResponse = buildErrorResponse(requestContext);
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
     * @param outTransport outbound message transport *
     * @param requestContext request context to which decoded information should be added
     *
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected void decodeRequest(LogoutRequestContext requestContext,
            HTTPInTransport inTransport, HTTPOutTransport outTransport) throws
            ProfileException {
        log.debug("Decoding message with decoder binding '{}'", getInboundBinding());

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
            SAMLMessageDecoder decoder =
                    getMessageDecoders().get(getInboundBinding());
            requestContext.setMessageDecoder(decoder);
            decoder.decode(requestContext);
            log.debug("Decoded request from relying party '{}'", requestContext.getInboundMessage());

            if (!(requestContext.getInboundSAMLMessage() instanceof LogoutRequest)) {
                log.warn("Incoming message was not a LogoutRequest, it was a {}", requestContext.getInboundSAMLMessage().getClass().getName());
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
                        "Invalid SAML LogoutRequest message."));
                throw new ProfileException("Invalid SAML LogoutRequest message.");
            }
        } catch (MessageDecodingException e) {
            String msg = "Error decoding logout request message";
            log.warn(msg, e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, msg));
            throw new ProfileException(msg);
        } catch (SecurityException e) {
            String msg = "Message did not meet security requirements";
            log.warn(msg, e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI, msg));
            throw new ProfileException(msg, e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            populateRequestContext(requestContext);
        }
    }

    protected class LogoutRequestContext
            extends BaseSAML2ProfileRequestContext<LogoutRequest, LogoutResponse, LogoutRequestConfiguration> {
    }
}
