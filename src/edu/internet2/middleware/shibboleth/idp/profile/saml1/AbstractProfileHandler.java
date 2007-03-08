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

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.MessageDecoder;
import org.opensaml.common.binding.MessageEncoder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.xml.XMLObjectBuilderFactory;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;

/**
 * Common implementation details for profile handlers.
 */
public abstract class AbstractProfileHandler implements ProfileHandler {

    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_11;

    /** Class logger. */
    private static Logger log = Logger.getLogger(AbstractProfileHandler.class);
    
    /** For building XML. */
    private XMLObjectBuilderFactory builderFactory;

    /** For generating random ids. */
    private SecureRandomIdentifierGenerator idGenerator;

    /** For decoding requests. */
    private MessageDecoder<ServletRequest> decoder;

    /** For encoding responses. */
    private MessageEncoder<ServletResponse> encoder;

    /** Relying party configuration. */
    private RelyingPartyConfiguration relyingPartyConfiguration;

    /** For resolving attributes. */
    private AttributeResolver resolver;

    /** To determine releasable attributes. */
    private FilteringEngine engine;

    /**
     * Default constructor.
     */
    public AbstractProfileHandler() {
        builderFactory = Configuration.getBuilderFactory();
        idGenerator = new SecureRandomIdentifierGenerator();
    }

    /**
     * Returns the XML builder factory.
     * 
     * @return Returns the builderFactory.
     */
    public XMLObjectBuilderFactory getBuilderFactory() {
        return builderFactory;
    }

    /**
     * Returns the id generator.
     * 
     * @return Returns the idGenerator.
     */
    public SecureRandomIdentifierGenerator getIdGenerator() {
        return idGenerator;
    }

    /**
     * Sets the decoder.
     * 
     * @param d <code>MessageDecoder</code>
     */
    public void setDecoder(MessageDecoder<ServletRequest> d) {
        decoder = d;
    }

    /**
     * Returns the decoder.
     * 
     * @return <code>MessageDecoder</code>
     */
    public MessageDecoder<ServletRequest> getDecoder() {
        return decoder;
    }

    /**
     * Sets the encoder.
     * 
     * @param e <code>MessageEncoder</code>
     */
    public void setEncoder(MessageEncoder<ServletResponse> e) {
        encoder = e;
    }

    /**
     * Returns the encoder.
     * 
     * @return <code>MessageEncoder</code>
     */
    public MessageEncoder<ServletResponse> getEncoder() {
        return encoder;
    }

    /**
     * Sets the attribute resolver.
     * 
     * @param r <code>AttributeResolver</code>
     */
    public void setAttributeResolver(AttributeResolver r) {
        resolver = r;
    }

    /**
     * Returns the attribute resolver.
     * 
     * @return <code>AttributeResolver</code>
     */
    public AttributeResolver getAttributeResolver() {
        return resolver;
    }

    /**
     * Sets the filter engine.
     * 
     * @param e <code>FilterEngine</code>
     */
    public void setFilterEngine(FilteringEngine e) {
        engine = e;
    }

    /**
     * Returns the filter engine.
     * 
     * @return <code>FilterEngine</code>
     */
    public FilteringEngine getFilteringEngine() {
        return engine;
    }

    /**
     * Returns the relying party configuration.
     * 
     * @return Returns the relyingParty.
     */
    public RelyingPartyConfiguration getRelyingPartyConfiguration() {
        return relyingPartyConfiguration;
    }

    /**
     * Sets the relying party configuration.
     * 
     * @param c The relyingParty to set.
     */
    public void setRelyingPartyConfiguration(RelyingPartyConfiguration c) {
        relyingPartyConfiguration = c;
    }
    
    /**
     * This decodes the attribute query message from the supplied request.
     * 
     * @param request <code>ServletRequest</code>
     * @return <code>SAMLObject</code>
     * @throws BindingException if the request cannot be decoded
     */
    protected SAMLObject decodeMessage(ServletRequest request) throws BindingException {
        // call decode method on decoder
        decoder.setRequest(request);
        decoder.decode();
        if (log.isDebugEnabled()) {
            log.debug("decoded servlet request");
        }

        // get SAMLMessage from the decoder
        final SAMLObject message = decoder.getSAMLMessage();
        if (log.isDebugEnabled()) {
            log.debug("retrieved attribute query message from decoder: " + message);
        }

        return message;
    }
    

    /**
     * This encodes the supplied response.
     * 
     * @param response <code>SAMLObject</code>
     * @throws BindingException if the response cannot be encoded
     */
    protected void encodeResponse(SAMLObject response) throws BindingException {
        encoder.setSAMLMessage(response);
        encoder.encode();
        if (log.isDebugEnabled()) {
            log.debug("encoded saml1 response");
        }
    }    
}
