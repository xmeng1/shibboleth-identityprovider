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

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import org.opensaml.Configuration;
import org.opensaml.common.binding.MessageDecoder;
import org.opensaml.common.binding.MessageEncoder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;

/**
 * Common implementation details for profile handlers.
 */
public abstract class AbstractProfileHandler implements ProfileHandler {

    /** For building XML objects. */
    private XMLObjectBuilderFactory builderFactory;
    
    /** For generating secure random ids. */
    private SecureRandomIdentifierGenerator idGenerator;        

    /** For decoding requests. */
    private MessageDecoder decoder;

    /** For encoding responses. */
    private MessageEncoder encoder;

    /** For resolving attributes. */
    private AttributeResolver resolver;
    
    /** To determine releasable attributes. */
    private FilteringEngine engine;
    
    /** */
    private MetadataProvider provider;
    
    
    /**
     * Default constructor.
     */
    public AbstractProfileHandler() {
        builderFactory = Configuration.getBuilderFactory();
        idGenerator = new SecureRandomIdentifierGenerator();        
    }
    
    
    /**
     * Sets the builder factory.
     * 
     *  @param f <code>XMLObjectBuilderFactory</code>
     */
    public void setBuilderFactory(XMLObjectBuilderFactory f) {
        builderFactory = f;    
    }

    
    /**
     * Returns the builder factory.
     * 
     * @return <code>XMLObjectBuilderFactory</code> 
     */
    public XMLObjectBuilderFactory getBuilderFactory() {
        return builderFactory;    
    }

    
    /**
     * Sets the id generator.
     * 
     *  @param g <code>SecureRandomIdentifierGenerator</code>
     */
    public void setIdGenerator(SecureRandomIdentifierGenerator g) {
        idGenerator = g;    
    }

    
    /**
     * Returns the id generator.
     * 
     * @return <code>SecureRandomIdentifierGenerator</code> 
     */
    public SecureRandomIdentifierGenerator getIdGenerator() {
        return idGenerator;    
    }

    
    /**
     * Sets the decoder.
     * 
     *  @param d <code>MessageDecoder</code>
     */
    public void setDecoder(MessageDecoder d) {
        decoder = d;    
    }

    
    /**
     * Returns the decoder.
     * 
     * @return <code>MessageDecoder</code> 
     */
    public MessageDecoder getDecoder() {
        return decoder;    
    }

    
    /**
     * Sets the encoder.
     * 
     *  @param e <code>MessageEncoder</code>
     */
    public void setEncoder(MessageEncoder e) {
        encoder = e;    
    }
    
    
    /**
     * Returns the encoder.
     * 
     * @return <code>MessageEncoder</code> 
     */
    public MessageEncoder getEncoder() {
        return encoder;    
    }
    

    /**
     * Sets the attribute resolver.
     * 
     *  @param r <code>AttributeResolver</code>
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
     *  @param e <code>FilterEngine</code>
     */
    public void setFilterEngine(FilteringEngine e) {
        engine = e;    
    }
    
    
    /**
     * Returns the filter engine.
     * 
     * @return <code>FilterEngine</code> 
     */    
    public FilteringEngine getFilterEngine() {
        return engine;    
    }

    
    /**
     * Sets the metadata provider.
     * 
     *  @param p <code>MetadataProvider</code>
     */
    public void setMetadataProvider(MetadataProvider p) {
        provider = p;    
    }

    
    /**
     * Returns the metadata provider.
     * 
     * @return <code>MetadataProvider</code> 
     */        
    public MetadataProvider getMetadataProvider() {
        return provider;    
    }
}
