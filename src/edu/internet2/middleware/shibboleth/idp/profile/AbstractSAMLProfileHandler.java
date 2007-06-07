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
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.decoding.MessageDecoderFactory;
import org.opensaml.common.binding.encoding.MessageEncoderFactory;
import org.opensaml.saml2.metadata.provider.MetadataProvider;

import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
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
     * Gets an ID generator which may be used for SAML assertions, requests, etc.
     * 
     * @param generator an ID generator which may be used for SAML assertions, requests, etc
     */
    public void setIdGenerator(IdentifierGenerator generator){
        idGenerator = generator;
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
    
    /**
     * Contextual object used to accumlate information as profile requests are being processed.
     * 
     * @param <StatusType> type of Status object
     */
    protected class SAMLProfileRequestContext<StatusType extends SAMLObject> extends ShibbolethProfileRequestContext {
        
        /** Role descriptor name that the asserting party is operating in. */
        private QName assertingPartyRole;
        
        /** Role descriptor name that the relying party is operating in. */
        private QName relyingPartyRole;
        
        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public SAMLProfileRequestContext(ProfileRequest<ServletRequest> request,
                ProfileResponse<ServletResponse> response) {
            super(request, response);
        }

        /**
         * Gets the role descriptor name that the asserting party is operating in.
         * 
         * @return role descriptor name that the asserting party is operating in
         */
        public QName getAssertingPartyRole() {
            return assertingPartyRole;
        }

        /**
         * Sets the role descriptor name that the asserting party is operating in.
         * 
         * @param role role descriptor name that the asserting party is operating in
         */
        public void setAssertingPartyRole(QName role) {
            assertingPartyRole = role;
        }

        /**
         * Gets the role descriptor name that the relying party is operating in.
         * 
         * @return role descriptor name that the relying party is operating in
         */
        public QName getRelyingPartyRole() {
            return relyingPartyRole;
        }

        /**
         * Sets the role descriptor name that the relying party is operating in.
         * 
         * @param role role descriptor name that the relying party is operating in
         */
        public void setRelyingPartyRole(QName role) {
            relyingPartyRole = role;
        }
    }
}