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
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext;
import edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextStorageHelper;
import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.httpclient.HttpClient;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.SOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.impl.BodyBuilder;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class SLOProfileHandler extends AbstractSAML2ProfileHandler {

    private static final Logger log =
            LoggerFactory.getLogger(SLOProfileHandler.class);
    private final SAMLObjectBuilder<SingleLogoutService> sloServiceBuilder;
    private final SAMLObjectBuilder<Status> statusBuilder;
    private final SAMLObjectBuilder<LogoutResponse> responseBuilder;

    public SLOProfileHandler() {
        super();
        sloServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) getBuilderFactory().getBuilder(
                SingleLogoutService.DEFAULT_ELEMENT_NAME);
        statusBuilder =
                (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        responseBuilder =
                (SAMLObjectBuilder<LogoutResponse>) getBuilderFactory().getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
    }

    @Override
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {

        LogoutRequest request =
                (LogoutRequest) requestContext.getInboundSAMLMessage();

        if (request != null) {
            request.getSessionIndexes(); //TODO session indexes?

            requestContext.setPeerEntityId(request.getIssuer().getValue());
            requestContext.setInboundSAMLMessageId(request.getID());
            if (request.getNameID() != null) {
                requestContext.setSubjectNameIdentifier(request.getNameID());
            } else {
                throw new ProfileException("Incoming Logout Request did not contain SAML2 NameID.");
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void populateRelyingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateRelyingPartyInformation(requestContext);

        EntityDescriptor relyingPartyMetadata =
                requestContext.getPeerEntityMetadata();
        if (relyingPartyMetadata != null) {
            requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setPeerEntityRoleMetadata(relyingPartyMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    @Override
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        Endpoint endpoint = null;

        if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {

            endpoint = sloServiceBuilder.buildObject();
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

    @Override
    public String getProfileId() {
        return LogoutRequestConfiguration.PROFILE_ID;
    }

    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        HttpServletRequest servletRequest =
                ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        SingleLogoutContext sloContext =
                SingleLogoutContextStorageHelper.getLoginContext(servletRequest);

        //TODO RelayState is lost?!
        //TODO unbind slo context
        //TODO front/back channel separation

        if (sloContext == null) {
            log.debug("Incoming request does not contain a single logout context, processing as first leg of request");
            startLogout(inTransport, outTransport);
        } else {
            log.debug("Incoming request contains a single logout context, processing as second leg of request");
            LogoutRequestContext requestContext =
                    buildRequestContext(sloContext, inTransport, outTransport);
            completeLogout(requestContext, inTransport, outTransport);
        }
    }

    /**
     * Start logout processing.
     * 
     * @param inTransport
     * @param outTransport
     * @throws ProfileException
     */
    protected void startLogout(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws
            ProfileException {

        LogoutRequestContext requestContext = new LogoutRequestContext();
        decodeRequest(requestContext, inTransport, outTransport);
        checkSamlVersion(requestContext);
        resolvePrincipal(requestContext);
        log.info("Processing logout request for principal '{}'.", requestContext.getPrincipalName());
        Session idpSession =
                getSessionManager().getSession(requestContext.getPrincipalName());
        if (idpSession == null) {
            log.warn("Cannot find IdP Session for Principal '{}'", requestContext.getPrincipalName());
            //TODO response
            throw new ProfileException("Cannot find IdP Session for principal");
        }

        if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
            initiateBackChannelLogout(inTransport, outTransport, requestContext, idpSession);
        } else {
            initiateFrontChannelLogout(inTransport, outTransport, requestContext, idpSession);
        }


    }

    /**
     * Issues back channel logout requests to session participants.
     *
     * @param inTransport
     * @param outTransport
     * @param requestContext
     * @param idpSession
     * @throws ProfileException
     */
    private void initiateBackChannelLogout(
            HTTPInTransport inTransport, HTTPOutTransport outTransport,
            LogoutRequestContext requestContext, Session idpSession)
            throws ProfileException {

        SingleLogoutContext sloContext =
                buildSingleLogoutContext(requestContext, idpSession);

        log.debug("Issuing Backchannel logout requests");
        for (String spEntityID : sloContext.getServiceStatus().keySet()) {
            log.debug("Trying SP: {}", spEntityID);

            //find SOAP endpoint for SingleLogoutService
            BasicEndpointSelector es = new BasicEndpointSelector();
            es.setEndpointType(SingleLogoutService.DEFAULT_ELEMENT_NAME);
            es.setMetadataProvider(getMetadataProvider());
            es.getSupportedIssuerBindings().add(SAMLConstants.SAML2_SOAP11_BINDING_URI);

            try {
                es.setEntityRoleMetadata(
                        getMetadataProvider().getRole(spEntityID, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
            } catch (MetadataProviderException ex) {
                log.info("Cannot get SAML2 metadata for SP '{}'.", spEntityID);
                continue;
            }
            Endpoint endpoint = es.selectEndpoint();
            if (endpoint == null) {
                log.info("Cannot get SAML2 SOAP SingleLogoutService endpoint for SP '{}'.", spEntityID);
                continue;
            }

            //Dirty hack to have access to the nameid, TODO: place nameid in serviceinformation?!

            requestContext.setInboundMessageIssuer(spEntityID);
            resolveAttributes(requestContext);
            NameID nameId = buildNameId(requestContext);

            log.debug("NameID for the principal: '{}'", nameId.getValue());


            SAMLObjectBuilder<LogoutRequest> requestBuilder =
                    (SAMLObjectBuilder<LogoutRequest>) getBuilderFactory().
                    getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
            SAMLObjectBuilder<LogoutResponse> responseBuilder =
                    (SAMLObjectBuilder<LogoutResponse>) getBuilderFactory().
                    getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
            
            LogoutRequest request = requestBuilder.buildObject();
            LogoutResponse response = responseBuilder.buildObject();
            
            DateTime issueInstant = new DateTime();
            request.setIssueInstant(issueInstant);
            request.setID(getIdGenerator().generateIdentifier());
            request.setVersion(SAMLVersion.VERSION_20);

            try {
                /*SAMLMessageEncoder encoder = new HTTPSOAP11Encoder();
                SAMLMessageDecoder decoder = new HTTPSOAP11Decoder(getParserPool());*/
                
                EnvelopeBuilder eb = new EnvelopeBuilder();
                BodyBuilder bb = new BodyBuilder();
                Envelope soapenv = eb.buildObject();
                
                Body soapbody = bb.buildObject();
                soapenv.setBody(soapbody);
                soapbody.getUnknownXMLObjects().add(request);

                SOAPMessageContext ctx = new BasicSOAPMessageContext();
                ctx.setCommunicationProfileId(getProfileId());
                ctx.setOutboundMessage(soapenv);
                ctx.setOutboundMessageIssuer(requestContext.getLocalEntityId());
                //ctx.setInboundMessage();

                //encoder.encode(ctx);

                HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
                httpClientBuilder.setConnectionTimeout(1000);
                httpClientBuilder.setContentCharSet("UTF-8");
                HttpClient httpClient = new HttpClient();
                
                HttpSOAPClient soapClient = new HttpSOAPClient(httpClient, getParserPool());
                soapClient.send(endpoint.getLocation(), ctx);

                XMLObject inboundMessage = ctx.getInboundMessage();
                
            } catch (SOAPException ex) {
                log.warn("Exception while encoding SAML Logout request", ex);
                continue;
            } catch (SecurityException ex) {
                log.warn("Exception while encoding SAML Logout request", ex);
                continue;
            } catch (Throwable t) {
                log.error("Exception while sending SAML Logout request", t);
            }
        }
    }

    /**
     * Issues front and back channel logout requests to session participants.
     * 
     * @param inTransport
     * @param outTransport
     * @param requestContext
     * @param idpSession
     * @throws ProfileException
     */
    private void initiateFrontChannelLogout(
            HTTPInTransport inTransport, HTTPOutTransport outTransport,
            LogoutRequestContext requestContext, Session idpSession)
            throws ProfileException {

        try {
            HttpServletRequest servletRequest =
                    ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
            SingleLogoutContext sloContext =
                    buildSingleLogoutContext(requestContext, idpSession);
            SingleLogoutContextStorageHelper.bindSingleLogoutContext(sloContext, servletRequest);

            RequestDispatcher dispatcher =
                    servletRequest.getRequestDispatcher("/SLOServlet"); //TODO!
            dispatcher.forward(servletRequest, ((HttpServletResponseAdapter) outTransport).getWrappedResponse());

        } catch (IOException ex) {
            log.error("Error forwarding SAML 2 Single Logout Request to the Logout Servlet", ex);
            throw new ProfileException("Error forwarding SAML 2 Single Logout Request to the Logout Servlet", ex);
        } catch (ServletException ex) {
            log.error("Error forwarding SAML 2 Single Logout Request to the Logout Servlet", ex);
            throw new ProfileException("Error forwarding SAML 2 Single Logout Request to the Logout Servlet", ex);
        }
    }

    /**
     * Complete logout processing.
     * 
     * @param inTransport
     * @param outTransport
     * @throws ProfileException
     */
    protected void completeLogout(LogoutRequestContext requestContext,
            HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        LogoutResponse samlResponse = buildLogoutResponse(requestContext);

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());

        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Builds new single log-out context for session store between logout events.
     *
     * @param requestContext
     * @param idpSession
     * @return
     */
    private SingleLogoutContext buildSingleLogoutContext(LogoutRequestContext requestContext, Session idpSession) {

        return new SingleLogoutContext(requestContext.getPeerEntityId(),
                requestContext.getInboundSAMLMessageId(), requestContext.getRelayState(),
                idpSession);
    }

    /**
     * Builds request context from information available after logout events.
     *
     * @param sloContext
     * @return
     */
    protected LogoutRequestContext buildRequestContext(SingleLogoutContext sloContext,
            HTTPInTransport in, HTTPOutTransport out) throws ProfileException {

        LogoutRequestContext requestContext = new LogoutRequestContext();

        requestContext.setCommunicationProfileId(getProfileId());
        requestContext.setMessageDecoder(getMessageDecoders().get(getInboundBinding()));
        requestContext.setInboundMessageTransport(in);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setOutboundMessageTransport(out);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setMetadataProvider(getMetadataProvider());
        requestContext.setInboundSAMLMessageId(sloContext.getRequestSAMLMessageID());
        requestContext.setInboundMessageIssuer(sloContext.getRequesterEntityID());

        return requestContext;
    }

    /**
     * Builds Logout Response.
     *
     * @param requestContext
     * @return
     * @throws edu.internet2.middleware.shibboleth.common.profile.ProfileException
     */
    protected LogoutResponse buildLogoutResponse(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {

        DateTime issueInstant = new DateTime();

        LogoutResponse logoutResponse = responseBuilder.buildObject();
        logoutResponse.setIssueInstant(issueInstant);
        populateStatusResponse(requestContext, logoutResponse);
        Status status = buildStatus(StatusCode.SUCCESS_URI, null, null);
        logoutResponse.setStatus(status);

        return logoutResponse;
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

    public class LogoutRequestContext
            extends BaseSAML2ProfileRequestContext<LogoutRequest, LogoutResponse, LogoutRequestConfiguration> {
    }
}
