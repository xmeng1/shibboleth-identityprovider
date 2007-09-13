/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.profile;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.log.Level;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;

import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractShibbolethProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * Base class for SAML profile handlers.
 */
public abstract class AbstractSAMLProfileHandler extends
        AbstractShibbolethProfileHandler<SAMLMDRelyingPartyConfigurationManager, Session> {

    /** SAML message audit log. */
    private final Logger auditLog = Logger.getLogger(AuditLogEntry.AUDIT_LOGGER_NAME);

    /** Class logger. */
    private final Logger log = Logger.getLogger(AbstractSAMLProfileHandler.class);

    /** Generator of IDs which may be used for SAML assertions, requests, etc. */
    private IdentifierGenerator idGenerator;

    /** All the SAML message decoders configured for the IdP. */
    private Map<String, SAMLMessageDecoder> messageDecoders;

    /** All the SAML message encoders configured for the IdP. */
    private Map<String, SAMLMessageEncoder> messageEncoders;

    /** SAML message binding used by inbound messages. */
    private String inboundBinding;

    /** SAML message bindings that may be used by outbound messages. */
    private List<String> supportedOutboundBindings;

    /** Constructor. */
    protected AbstractSAMLProfileHandler() {
        super();
    }

    /**
     * Gets the audit log for this handler.
     * 
     * @return audit log for this handler
     */
    protected Logger getAduitLog() {
        return auditLog;
    }

    /**
     * Gets an ID generator which may be used for SAML assertions, requests, etc.
     * 
     * @return ID generator
     */
    public IdentifierGenerator getIdGenerator() {
        return idGenerator;
    }

    /**
     * Gets the SAML message binding used by inbound messages.
     * 
     * @return SAML message binding used by inbound messages
     */
    public String getInboundBinding() {
        return inboundBinding;
    }

    /**
     * Gets all the SAML message decoders configured for the IdP indexed by SAML binding URI.
     * 
     * @return SAML message decoders configured for the IdP indexed by SAML binding URI
     */
    public Map<String, SAMLMessageDecoder> getMessageDecoders() {
        return messageDecoders;
    }

    /**
     * Gets all the SAML message encoders configured for the IdP indexed by SAML binding URI.
     * 
     * @return SAML message encoders configured for the IdP indexed by SAML binding URI
     */
    public Map<String, SAMLMessageEncoder> getMessageEncoders() {
        return messageEncoders;
    }

    /**
     * A convenience method for retrieving the SAML metadata provider from the relying party manager.
     * 
     * @return the metadata provider or null
     */
    public MetadataProvider getMetadataProvider() {
        SAMLMDRelyingPartyConfigurationManager rpcManager = getRelyingPartyConfigurationManager();
        if (rpcManager != null) {
            return rpcManager.getMetadataProvider();
        }

        return null;
    }

    /**
     * Gets the SAML message bindings that may be used by outbound messages.
     * 
     * @return SAML message bindings that may be used by outbound messages
     */
    public List<String> getSupportedOutboundBindings() {
        return supportedOutboundBindings;
    }

    /**
     * Gets the user's session, if there is one.
     * 
     * @param inTransport current inbound transport
     * 
     * @return user's session
     */
    protected Session getUserSession(InTransport inTransport) {
        String sessionId = getUserSessionId(inTransport);
        return getSessionManager().getSession(sessionId);
    }

    /**
     * Gets the user's session ID from the current request.
     * 
     * @param inTransport current inbound transport
     * 
     * @return user's session ID
     */
    protected String getUserSessionId(InTransport inTransport) {
        HttpServletRequest rawRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();

        if (rawRequest != null) {
            return (String) rawRequest.getSession().getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        }

        return null;
    }

    /**
     * Gets an ID generator which may be used for SAML assertions, requests, etc.
     * 
     * @param generator an ID generator which may be used for SAML assertions, requests, etc
     */
    public void setIdGenerator(IdentifierGenerator generator) {
        idGenerator = generator;
    }

    /**
     * Sets the SAML message binding used by inbound messages.
     * 
     * @param binding SAML message binding used by inbound messages
     */
    public void setInboundBinding(String binding) {
        inboundBinding = binding;
    }

    /**
     * Sets all the SAML message decoders configured for the IdP indexed by SAML binding URI.
     * 
     * @param decoders SAML message decoders configured for the IdP indexed by SAML binding URI
     */
    public void setMessageDecoders(Map<String, SAMLMessageDecoder> decoders) {
        messageDecoders = decoders;
    }

    /**
     * Sets all the SAML message encoders configured for the IdP indexed by SAML binding URI.
     * 
     * @param encoders SAML message encoders configured for the IdP indexed by SAML binding URI
     */
    public void setMessageEncoders(Map<String, SAMLMessageEncoder> encoders) {
        messageEncoders = encoders;
    }

    /**
     * Sets the SAML message bindings that may be used by outbound messages.
     * 
     * @param bindings SAML message bindings that may be used by outbound messages
     */
    public void setSupportedOutboundBindings(List<String> bindings) {
        supportedOutboundBindings = bindings;
    }

    /**
     * Encodes the request's SAML response and writes it to the servlet response.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if no message encoder is registered for this profiles binding
     */
    protected void encodeResponse(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        try {
            Endpoint peerEndpoint = requestContext.getPeerEntityEndpoint();
            if (peerEndpoint == null) {
                log.error("No return endpoint available for relying party " + requestContext.getInboundMessageIssuer());
                throw new ProfileException("No peer endpoint available to which to send SAML response");
            }

            SAMLMessageEncoder encoder = getMessageEncoders().get(requestContext.getPeerEntityEndpoint().getBinding());
            if (encoder == null) {
                log.error("No outbound message encoder configured for binding "
                        + requestContext.getPeerEntityEndpoint().getBinding());
                throw new ProfileException("No outbound message encoder configured for binding "
                        + requestContext.getPeerEntityEndpoint().getBinding());
            }

            if (log.isDebugEnabled()) {
                log.debug("Encoding response to SAML request " + requestContext.getInboundSAMLMessageId()
                        + " from relying party " + requestContext.getInboundMessageIssuer() + " with outbound binding "
                        + encoder.getBindingURI());
            }

            requestContext.setMessageEncoder(encoder);
            encoder.encode(requestContext);
        } catch (MessageEncodingException e) {
            throw new ProfileException("Unable to encode response to relying party: "
                    + requestContext.getInboundMessageIssuer(), e);
        }
    }

    /**
     * Writes an aduit log entry indicating the successful response to the attribute request.
     * 
     * @param context current request context
     */
    protected void writeAuditLogEntry(BaseSAMLProfileRequestContext context) {
        AuditLogEntry auditLogEntry = new AuditLogEntry();
        auditLogEntry.setMessageProfile(getProfileId());
        auditLogEntry.setPrincipalAuthenticationMethod(context.getPrincipalAuthenticationMethod());
        auditLogEntry.setPrincipalName(context.getPrincipalName());
        auditLogEntry.setAssertingPartyId(context.getLocalEntityId());
        auditLogEntry.setRelyingPartyId(context.getInboundMessageIssuer());
        auditLogEntry.setRequestBinding(context.getMessageDecoder().getBindingURI());
        auditLogEntry.setRequestId(context.getInboundSAMLMessageId());
        auditLogEntry.setResponseBinding(context.getMessageEncoder().getBindingURI());
        auditLogEntry.setResponseId(context.getOutboundSAMLMessageId());
        if (context.getReleasedAttributes() != null) {
            auditLogEntry.getReleasedAttributes().addAll(context.getReleasedAttributes());
        }
        getAduitLog().log(Level.CRITICAL, auditLogEntry);
    }
}