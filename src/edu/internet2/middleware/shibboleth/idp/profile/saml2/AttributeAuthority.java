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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletRequest;

import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.xml.XMLObjectBuilderFactory;

import edu.internet2.middleware.shibboleth.common.attribute.Attribute;
import edu.internet2.middleware.shibboleth.common.attribute.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.SAML2AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.BasicFilterContext;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.ResolutionContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;

/**
 * SAML 2.0 Attribute Authority.
 */
public class AttributeAuthority implements SAML2AttributeAuthority {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AttributeAuthority.class);

    /** For building XML objects. */
    private XMLObjectBuilderFactory builderFactory;

    /** Attribute resolver. */
    private AttributeResolver attributeResolver;

    /** Security policy. */
    private SecurityPolicy securityPolicy;

    /** Relying party configuration. */
    private RelyingPartyConfiguration relyingPartyConfiguration;

    /** To determine releasable attributes. */
    private FilteringEngine filteringEngine;

    /** Servlet request containing the SAML message. */
    private ServletRequest request;

    /**
     * Default constructor.
     */
    public AttributeAuthority() {
        builderFactory = Configuration.getBuilderFactory();
    }

    /**
     * Gets the attribute resolver.
     * 
     * @return Returns the attributeResolver.
     */
    public AttributeResolver getAttributeResolver() {
        return attributeResolver;
    }

    /**
     * Sets the attribute resolver.
     * 
     * @param ar The attributeResolver to set.
     */
    public void setAttributeResolver(AttributeResolver ar) {
        this.attributeResolver = ar;
    }

    /**
     * Gets the request.
     * 
     * @return Returns the request.
     */
    public ServletRequest getRequest() {
        return request;
    }

    /**
     * Sets the request.
     * 
     * @param r The request to set.
     */
    public void setRequest(ServletRequest r) {
        this.request = r;
    }

    /**
     * Gets the filtering engine.
     * 
     * @return Returns the filteringEngine.
     */
    public FilteringEngine getFilteringEngine() {
        return filteringEngine;
    }

    /**
     * Sets the filtering engine.
     * 
     * @param fe The filteringEngine to set.
     */
    public void setFilteringEngine(FilteringEngine fe) {
        this.filteringEngine = fe;
    }

    /**
     * Gets the relying party configuration.
     * 
     * @return Returns the relyingPartyConfiguration.
     */
    public RelyingPartyConfiguration getRelyingPartyConfiguration() {
        return relyingPartyConfiguration;
    }

    /**
     * Sets the relying party configuration.
     * 
     * @param rpc The relyingPartyConfiguration to set.
     */
    public void setRelyingPartyConfiguration(RelyingPartyConfiguration rpc) {
        this.relyingPartyConfiguration = rpc;
    }

    /**
     * Gets the security policy.
     * 
     * @return Returns the securityPolicy.
     */
    public SecurityPolicy getSecurityPolicy() {
        return securityPolicy;
    }

    /**
     * Sets the security policy.
     * 
     * @param sp The securityPolicy to set.
     */
    public void setSecurityPolicy(SecurityPolicy sp) {
        this.securityPolicy = sp;
    }

    /** {@inheritDoc} */
    public AttributeStatement performAttributeQuery(AttributeQuery query) throws AttributeResolutionException,
            FilteringException {
        // get attributes from the message
        Set<String> releasedAttributes = getMessageAttributes(query.getAttributes());

        // create resolution context from the resolver, using nameid element from the attribute query
        ResolutionContext resolutionContext = getAttributeResolver().createResolutionContext(
                query.getSubject().getNameID(), securityPolicy.getIssuer().toString(), request);
        // get resolved attributes from the resolver
        Map<String, Attribute> resolvedAttributes = getResolvedAttributes(resolutionContext, releasedAttributes);

        // filter attributes
        BasicFilterContext filteringContext = new BasicFilterContext(query.getSubject().getNameID().toString(),
                getRelyingPartyConfiguration().getProviderID(), query.getSubject().getNameID().toString(),
                resolvedAttributes);
        Set<Attribute> filteredAttributes = filteringEngine.filterAttributes(filteringContext);

        // encode attributes
        List<org.opensaml.saml2.core.Attribute> encodedAttributes = encodeAttributes(filteredAttributes);

        // return attribute statement
        return buildAttributeStatement(encodedAttributes);
    }

    /** {@inheritDoc} */
    public AttributeStatement performAttributeQuery(String entity, NameID subject) throws AttributeResolutionException,
            FilteringException {
        return null;
    }

    /** {@inheritDoc} */
    public String getAttributeIDBySAMLAttribute(org.opensaml.saml2.core.Attribute attribute) {
        return attribute.getName();
    }

    /** {@inheritDoc} */
    public org.opensaml.saml2.core.Attribute getSAMLAttributeByAttributeID(String id) {
        SAMLObjectBuilder<org.opensaml.saml2.core.Attribute> attributeBuilder = (SAMLObjectBuilder<org.opensaml.saml2.core.Attribute>) builderFactory
                .getBuilder(org.opensaml.saml2.core.Attribute.DEFAULT_ELEMENT_NAME);
        org.opensaml.saml2.core.Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(id);
        return attribute;
    }

    /**
     * This parses the attribute name from the supplied list of attributes.
     * 
     * @param messageAttributes <code>List</code>
     * @return <code>Set</code>
     */
    private Set<String> getMessageAttributes(List<org.opensaml.saml2.core.Attribute> messageAttributes) {
        final Set<String> attributes = new HashSet<String>(messageAttributes.size());
        for (org.opensaml.saml2.core.Attribute a : messageAttributes) {
            attributes.add(getAttributeIDBySAMLAttribute(a));
        }
        if (log.isDebugEnabled()) {
            log.debug("message contains the following attributes: " + attributes);
        }
        // TODO go to metadata for other attributes
        return attributes;
    }

    /**
     * This resolves the supplied attribute names using the supplied resolution context.
     * 
     * @param context <code>ResolutionContext</code>
     * @param releasedAttributes <code>Set</code>
     * @return <code>Map</code> of attribute ID to attribute
     * @throws AttributeResolutionException if an attribute cannot be resolved
     */
    private Map<String, Attribute> getResolvedAttributes(ResolutionContext context, Set<String> releasedAttributes)
            throws AttributeResolutionException {
        // call Attribute resolver
        Set<Attribute> resolvedAttributes = getAttributeResolver().resolveAttributes(releasedAttributes, context);
        if (log.isDebugEnabled()) {
            log.debug("attribute resolver resolved the following attributes: " + resolvedAttributes);
        }

        Map<String, Attribute> attrs = new HashMap<String, Attribute>();
        for (Attribute attr : resolvedAttributes) {
            attrs.put(attr.getId(), attr);
        }
        return attrs;
    }

    /**
     * This encodes the supplied list of attributes with that attribute's SAML2 encoder.
     * 
     * @param resolvedAttributes <code>Set</code>
     * @return <code>List</code> of core attributes
     */
    private List<org.opensaml.saml2.core.Attribute> encodeAttributes(Set<Attribute> resolvedAttributes) {
        // encode attributes
        List<org.opensaml.saml2.core.Attribute> encodedAttributes = new ArrayList<org.opensaml.saml2.core.Attribute>();

        for (Attribute attr : resolvedAttributes) {
            AttributeEncoder<org.opensaml.saml2.core.Attribute> enc = attr
                    .getEncoderByCategory(SAML2AttributeEncoder.CATEGORY);
            encodedAttributes.add(enc.encode(attr));
        }
        if (log.isDebugEnabled()) {
            log.debug("attribute encoder encoded the following attributes: " + encodedAttributes);
        }
        return encodedAttributes;
    }

    /**
     * This builds the attribute statement for this SAML request.
     * 
     * @param encodedAttributes <code>List</code> of attributes
     * @return <code>AttributeStatement</code>
     */
    private AttributeStatement buildAttributeStatement(List<org.opensaml.saml2.core.Attribute> encodedAttributes) {
        SAMLObjectBuilder<AttributeStatement> statementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        AttributeStatement statement = statementBuilder.buildObject();
        statement.getAttributes().addAll(encodedAttributes);
        return statement;
    }
}
