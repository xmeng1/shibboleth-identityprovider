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

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.binding.decoding.MessageDecoderFactory;
import org.opensaml.common.binding.encoding.MessageEncoderFactory;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.metadata.provider.MetadataProvider;

import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
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

    /** Factory of message decoders. */
    private MessageDecoderFactory decoderFactory;

    /** Factory of message encoders. */
    private MessageEncoderFactory encoderFactory;

    /** Constructor. */
    protected AbstractSAMLProfileHandler() {
        super();
        idGenerator = new SecureRandomIdentifierGenerator();
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
     * Gets the factory used to build new message decoders.
     * 
     * @return factory used to build new message decoders
     */
    public MessageDecoderFactory getMessageDecoderFactory() {
        return decoderFactory;
    }

    /**
     * Sets the factory used to build new message decoders.
     * 
     * @param factory factory used to build new message decoders
     */
    public void setMessageDecoderFactory(MessageDecoderFactory factory) {
        decoderFactory = factory;
    }

    /**
     * Gets the factory used to build message encoders.
     * 
     * @return factory used to build message encoders
     */
    public MessageEncoderFactory getMessageEncoderFactory() {
        return encoderFactory;
    }

    /**
     * Sets the factory used to build message encoders.
     * 
     * @param factory factory used to build message encoders
     */
    public void setMessageEncoderFactory(MessageEncoderFactory factory) {
        encoderFactory = factory;
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
     * Gets the audit log for this handler.
     * 
     * @return audit log for this handler
     */
    protected Logger getAduitLog() {
        return auditLog;
    }

    /**
     * Gets the user's session ID from the current request.
     * 
     * @param request current request
     * 
     * @return user's session ID
     */
    protected String getUserSessionId(ProfileRequest<ServletRequest> request) {
        HttpServletRequest rawRequest = (HttpServletRequest) request.getRawRequest();
        if (rawRequest != null) {
            return (String) rawRequest.getSession().getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        }

        return null;
    }
}