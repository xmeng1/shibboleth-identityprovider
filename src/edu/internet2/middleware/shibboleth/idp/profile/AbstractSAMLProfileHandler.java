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

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;

import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractShibbolethProfileHandler;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * Base class for SAML profile handlers.
 */
public abstract class AbstractSAMLProfileHandler extends
        AbstractShibbolethProfileHandler<SAMLMDRelyingPartyConfigurationManager, Session> {

    /** SAML message audit log. */
    private final Logger auditLog = Logger.getLogger(AuditLogEntry.AUDIT_LOGGER_NAME);

    /** Generator of IDs which may be used for SAML assertions, requests, etc. */
    private IdentifierGenerator idGenerator;

    /** Decoder used to extract message information from the inbound transport. */
    private SAMLMessageDecoder messageDecoder;

    /** Encoder used to bind information to the outbound message transport. */
    private SAMLMessageEncoder messageEncoder;

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
     * Gets the decoder used to extract message information from the inbound transport.
     * 
     * @return decoder used to extract message information from the inbound transport
     */
    public SAMLMessageDecoder getMessageDecoder() {
        return messageDecoder;
    }

    /**
     * Gets the encoder used to bind information to the outbound message transport.
     * 
     * @return encoder used to bind information to the outbound message transport
     */
    public SAMLMessageEncoder getMessageEncoder() {
        return messageEncoder;
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
     * Gets the user's session, if there is one.
     * 
     * @param inTransport current inbound transport
     * 
     * @return user's session
     */
    protected Session getUserSession(InTransport inTransport){
        String sessionId = getUserSessionId(inTransport);
        return getSessionManager().getSession(sessionId);
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
     * Sets the decoder used to extract message information from the inbound transport.
     * 
     * @param decoder decoder used to extract message information from the inbound transport
     */
    public void setMessageDecoder(SAMLMessageDecoder decoder) {
        messageDecoder = decoder;
    }

    /**
     * Sets the encoder used to bind information to the outbound message transport.
     * 
     * @param encoder encoder used to bind information to the outbound message transport
     */
    public void setMessageEncoder(SAMLMessageEncoder encoder) {
        messageEncoder = encoder;
    }
}