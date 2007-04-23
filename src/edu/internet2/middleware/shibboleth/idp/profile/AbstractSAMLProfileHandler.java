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

import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.binding.MessageDecoder;
import org.opensaml.common.binding.MessageEncoder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.metadata.provider.MetadataProvider;

import edu.internet2.middleware.shibboleth.common.profile.AbstractProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * Base class for SAML profile handlers.
 */
public abstract class AbstractSAMLProfileHandler extends
        AbstractProfileHandler<SAMLMDRelyingPartyConfigurationManager, Session> {

    /** Generator of IDs which may be used for SAML assertions, requests, etc. */
    private IdentifierGenerator idGenerator;

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
     * Populates the given message decoder with the profile handler's metadata provider.
     * 
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    protected void populateMessageDecoder(MessageDecoder<ServletRequest> decoder){
        super.populateMessageDecoder(decoder);
        decoder.setMetadataProvider(getMetadataProvider());
    }
    
    /**
     * Populates the given message encoder with the profile handler's metadata provider.
     * 
     * {@inheritDoc}
     */
    protected void populateMessageEncoder(MessageEncoder<ServletResponse> encoder) {
        super.populateMessageEncoder(encoder);
        encoder.setMetadataProvider(getMetadataProvider());
    }

    /**
     * Gets the message decoder to use in this query.
     * 
     * @param request attribute request
     * 
     * @return message decoder to use in this query
     * 
     * @throws ProfileException thrown if a message decoder can not be created for the given request
     */
    protected abstract MessageDecoder<ServletRequest> getMessageDecoder(ProfileRequest<ServletRequest> request)
            throws ProfileException;

    /**
     * Gets the message encoder to use in this query.
     * 
     * @param response attribute query response
     * 
     * @return message encoder to use in this query
     * 
     * @throws ProfileException thrown if a message encoder can not be created for the given request
     */
    protected abstract MessageEncoder<ServletResponse> getMessageEncoder(ProfileResponse<ServletResponse> response)
            throws ProfileException;

    /**
     * Gets the user's session ID from the current request.
     * 
     * @param request current request
     * 
     * @return user's session ID
     */
    protected abstract String getUserSessionId(ProfileRequest<ServletRequest> request);
}