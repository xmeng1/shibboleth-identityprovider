/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.profile;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AuthnAuthorityDescriptor;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCredentialResolverFactory;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.SAMLNameIdentifierEncoder;
import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractShibbolethProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartySecurityPolicyResolver;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.AbstractSAMLProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.CryptoOperationRequirementLevel;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * Base class for SAML profile handlers.
 */
public abstract class AbstractSAMLProfileHandler extends
        AbstractShibbolethProfileHandler<SAMLMDRelyingPartyConfigurationManager, Session> {

    /** SAML message audit log. */
    private final Logger auditLog = LoggerFactory.getLogger(AuditLogEntry.AUDIT_LOGGER_NAME);

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractSAMLProfileHandler.class);

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

    /** Resolver used to determine active security policy for an incoming request. */
    private SecurityPolicyResolver securityPolicyResolver;

    /** Credential resolver for resolving keys from metadata. */
    private MetadataCredentialResolver metadataCredentialResolver;

    /** Constructor. */
    protected AbstractSAMLProfileHandler() {
        super();
    }

    /**
     * Gets the resolver used to determine active security policy for an incoming request.
     * 
     * @return resolver used to determine active security policy for an incoming request
     */
    public SecurityPolicyResolver getSecurityPolicyResolver() {
        if (securityPolicyResolver == null) {
            setSecurityPolicyResolver(new RelyingPartySecurityPolicyResolver(getRelyingPartyConfigurationManager()));
        }

        return securityPolicyResolver;
    }

    /**
     * Sets the resolver used to determine active security policy for an incoming request.
     * 
     * @param resolver resolver used to determine active security policy for an incoming request
     */
    public void setSecurityPolicyResolver(SecurityPolicyResolver resolver) {
        securityPolicyResolver = resolver;
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
     * A convenience method for obtaining a metadata credential resolver for the current metadata provider.
     * 
     * @return the metadata credential resolver or null
     */
    public MetadataCredentialResolver getMetadataCredentialResolver() {
        // It's advisable to cache the metadata cred resolver instance from the factory
        // for the life of the profile handler. See SIDP-428.
        synchronized (this) {
            if (metadataCredentialResolver == null) {
                MetadataCredentialResolverFactory mcrFactory = MetadataCredentialResolverFactory.getFactory();
                MetadataProvider metadataProvider = getMetadataProvider();
                metadataCredentialResolver = mcrFactory.getInstance(metadataProvider);
            }
        }
        return metadataCredentialResolver;
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
        HttpServletRequest rawRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        return (Session) rawRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
    }

    /**
     * Gets the user's session based on their principal name.
     * 
     * @param principalName user's principal name
     * 
     * @return the user's session
     */
    protected Session getUserSession(String principalName) {
        return getSessionManager().getSession(principalName);
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

    /** {@inheritDoc} */
    public RelyingPartyConfiguration getRelyingPartyConfiguration(String relyingPartyId) {
        try {
            if (getMetadataProvider().getEntityDescriptor(relyingPartyId) == null) {
                log.warn("No metadata for relying party {}, treating party as anonymous", relyingPartyId);
                return getRelyingPartyConfigurationManager().getAnonymousRelyingConfiguration();
            }
        } catch (MetadataProviderException e) {
            log.error("Unable to look up relying party metadata", e);
            return null;
        }

        return super.getRelyingPartyConfiguration(relyingPartyId);
    }

    /**
     * Populates the request context with information.
     * 
     * This method requires the the following request context properties to be populated: inbound message transport,
     * peer entity ID, metadata provider
     * 
     * This methods populates the following request context properties: user's session, user's principal name, service
     * authentication method, peer entity metadata, relying party configuration, local entity ID, outbound message
     * issuer, local entity metadata
     * 
     * @param requestContext current request context
     * @throws ProfileException thrown if there is a problem looking up the relying party's metadata
     */
    protected void populateRequestContext(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        populateRelyingPartyInformation(requestContext);
        populateAssertingPartyInformation(requestContext);
        populateSAMLMessageInformation(requestContext);
        populateProfileInformation(requestContext);
        populateUserInformation(requestContext);
    }

    /**
     * Populates the request context with information about the relying party.
     * 
     * This method requires the the following request context properties to be populated: inbound message issuer
     * 
     * This methods populates the following request context properties: peer entityID, peer entity metadata,
     * relying party configuration
     * 
     * @param requestContext current request context
     * @throws ProfileException thrown if there is a problem looking up the relying party's metadata
     */
    protected void populateRelyingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        MetadataProvider metadataProvider = requestContext.getMetadataProvider();
        String relyingPartyId = requestContext.getInboundMessageIssuer();
        requestContext.setPeerEntityId(relyingPartyId);

        EntityDescriptor relyingPartyMetadata;
        try {
            relyingPartyMetadata = metadataProvider.getEntityDescriptor(relyingPartyId);
            requestContext.setPeerEntityMetadata(relyingPartyMetadata);
        } catch (MetadataProviderException e) {
            log.error("Error looking up metadata for relying party " + relyingPartyId, e);
            throw new ProfileException("Error looking up metadata for relying party " + relyingPartyId);
        }

        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
        if (rpConfig == null) {
            log.error("Unable to retrieve relying party configuration data for entity with ID {}", relyingPartyId);
            throw new ProfileException("Unable to retrieve relying party configuration data for entity with ID "
                    + relyingPartyId);
        }
        requestContext.setRelyingPartyConfiguration(rpConfig);
    }

    /**
     * Populates the request context with information about the asserting party. Unless overridden,
     * {@link #populateRequestContext(BaseSAMLProfileRequestContext)} has already invoked
     * {@link #populateRelyingPartyInformation(BaseSAMLProfileRequestContext)} has already been invoked and the
     * properties it provides are available in the request context.
     * 
     * This method requires the the following request context properties to be populated: metadata provider, relying
     * party configuration
     * 
     * This methods populates the following request context properties: local entity ID, outbound message issuer, local
     * entity metadata
     * 
     * @param requestContext current request context
     * @throws ProfileException thrown if there is a problem looking up the asserting party's metadata
     */
    protected void populateAssertingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        String assertingPartyId = requestContext.getRelyingPartyConfiguration().getProviderId();
        requestContext.setLocalEntityId(assertingPartyId);
        requestContext.setOutboundMessageIssuer(assertingPartyId);

        try {
            EntityDescriptor localEntityDescriptor = requestContext.getMetadataProvider().getEntityDescriptor(
                    assertingPartyId);
            if (localEntityDescriptor != null) {
                requestContext.setLocalEntityMetadata(localEntityDescriptor);
            }
        } catch (MetadataProviderException e) {
            log.error("Error looking up metadata for asserting party " + assertingPartyId, e);
            throw new ProfileException("Error looking up metadata for asserting party " + assertingPartyId);
        }
    }

    /**
     * Populates the request context with information from the inbound SAML message. Unless overridden,
     * {@link #populateRequestContext(BaseSAMLProfileRequestContext)} has already invoked
     * {@link #populateRelyingPartyInformation(BaseSAMLProfileRequestContext)},and
     * {@link #populateAssertingPartyInformation(BaseSAMLProfileRequestContext)} have already been invoked and the
     * properties they provide are available in the request context.
     * 
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is a problem populating the request context with information
     */
    protected abstract void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException;

    /**
     * Populates the request context with the information about the profile. Unless overridden,
     * {@link #populateRequestContext(BaseSAMLProfileRequestContext)} has already invoked
     * {@link #populateRelyingPartyInformation(BaseSAMLProfileRequestContext)},
     * {@link #populateAssertingPartyInformation(BaseSAMLProfileRequestContext)}, and
     * {@link #populateSAMLMessageInformation(BaseSAMLProfileRequestContext)} have already been invoked and the
     * properties they provide are available in the request context.
     * 
     * This method requires the the following request context properties to be populated: relying party configuration
     * 
     * This methods populates the following request context properties: communication profile ID, profile configuration,
     * outbound message artifact type, peer entity endpoint
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is a problem populating the profile information
     */
    protected void populateProfileInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        AbstractSAMLProfileConfiguration profileConfig = (AbstractSAMLProfileConfiguration) requestContext
                .getRelyingPartyConfiguration().getProfileConfiguration(getProfileId());
        if (profileConfig != null) {
            requestContext.setProfileConfiguration(profileConfig);
            requestContext.setOutboundMessageArtifactType(profileConfig.getOutboundArtifactType());
        }

        Endpoint endpoint = selectEndpoint(requestContext);
        if (endpoint == null) {
            log.error("No return endpoint available for relying party {}", requestContext.getInboundMessageIssuer());
            throw new ProfileException("No peer endpoint available to which to send SAML response");
        }
        requestContext.setPeerEntityEndpoint(endpoint);
    }

    /**
     * Attempts to select the most fitting name identifier attribute, and associated encoder, for a request. If no
     * attributes for the request subject are available no name identifier is constructed. If a specific name format is
     * required, as returned by {@link #getRequiredNameIDFormat(BaseSAMLProfileRequestContext)}, then either an
     * attribute with an encoder supporting that format is selected or an exception is thrown. If no specific format is
     * required then an attribute supporting a format listed as supported by the relying party is used. If the relying
     * party does not list any supported formats then any attribute supporting the correct name identifier type is used.
     * 
     * @param <T> type of name identifier encoder the attribute must support
     * @param nameIdEncoderType type of name identifier encoder the attribute must support
     * @param requestContext the current request context
     * 
     * @return the select attribute, and its encoder, to be used to build the name identifier
     * 
     * @throws ProfileException thrown if a specific name identifier format was required but not supported
     */
    protected <T extends SAMLNameIdentifierEncoder> Pair<BaseAttribute, T> selectNameIDAttributeAndEncoder(
            Class<T> nameIdEncoderType, BaseSAMLProfileRequestContext requestContext) throws ProfileException {

        Collection<BaseAttribute<?>> principalAttributes;
        if (requestContext.getAttributes() == null) {
            principalAttributes = Collections.emptyList();
        } else {
            principalAttributes = new ArrayList<BaseAttribute<?>>(requestContext.getAttributes().values());
        }

        filterNameIDAttributesByProtocol(principalAttributes, nameIdEncoderType);

        String requiredNameFormat = DatatypeHelper.safeTrimOrNullString(getRequiredNameIDFormat(requestContext));
        if (requiredNameFormat != null) {
            log.debug(
                    "Attempting to select name identifier attribute for relying party '{}' that requires format '{}'",
                    requestContext.getInboundMessageIssuer(), requiredNameFormat);
            filterNameIDAttributesByFormats(principalAttributes, Collections.singleton(requiredNameFormat));
            if (principalAttributes.isEmpty()) {
                String requiredNameFormatErr = "No attribute of principal '" + requestContext.getPrincipalName()
                        + "' can be encoded in to a NameIdentifier of " + "required format '" + requiredNameFormat
                        + "' for relying party '" + requestContext.getInboundMessageIssuer() + "'";
                log.warn(requiredNameFormatErr);
                throw new ProfileException(requiredNameFormatErr);
            }
        } else {
            filterNameIDAttributesByFormats(principalAttributes, getSupportedNameFormats(requestContext));
        }

        Pair<BaseAttribute, T> nameIdAttributeAndEncoder = selectNameIDAttributeAndEncoder(principalAttributes,
                nameIdEncoderType, requestContext.getRelyingPartyConfiguration().getNameIdFormatPrecedence());
        if (nameIdAttributeAndEncoder != null) {
            log.debug("Name identifier for relying party '{}' will be built from attribute '{}'",
                    requestContext.getInboundMessageIssuer(), nameIdAttributeAndEncoder.getFirst().getId());
        } else {
            log.debug(
                    "No attributes for principal '{}' support encoding into a supported name identifier format for relying party '{}'",
                    requestContext.getPrincipalName(), requestContext.getInboundMessageIssuer());
        }
        return nameIdAttributeAndEncoder;
    }

    /**
     * Filters a collection of attributes removing those attributes which do not have an associated encoder of a given
     * type.
     * 
     * @param <T> the type of the encoder
     * @param attributes the attributes to be filtered, may not contain null values
     * @param nameIdEncoderType the type of the encoder, may not be null
     * 
     * @throws ProfileException
     */
    protected <T extends SAMLNameIdentifierEncoder> void filterNameIDAttributesByProtocol(
            Collection<BaseAttribute<?>> attributes, Class<T> nameIdEncoderType) {
        if(attributes.isEmpty()){
            return;
        }
        
        log.debug("Filtering out potential name identifier attributes which can not be encoded by {}",
                nameIdEncoderType.getName());

        BaseAttribute<?> attribute;

        Iterator<BaseAttribute<?>> attributeItr = attributes.iterator();
        ATTRIBS: while (attributeItr.hasNext()) {
            attribute = attributeItr.next();
            for (AttributeEncoder encoder : attribute.getEncoders()) {
                if (encoder == null) {
                    continue;
                }

                if (nameIdEncoderType.isInstance(encoder)) {
                    log.debug("Retaining attribute {} which may be encoded to via {}", attribute.getId(),
                            nameIdEncoderType.getName());
                    continue ATTRIBS;
                }
            }
            log.debug("Removing attribute {}, it can not be encoded via {}", attribute.getId(),
                    nameIdEncoderType.getName());
            attributeItr.remove();
        }
    }

    /**
     * Filters a collection of attributes removing those attributes that can not be encoded in to a name identifier of
     * an acceptable format.
     * 
     * @param attributes the attributes to be filtered, may not contain null values
     * @param acceptableFormats name identifier formats which are acceptable, a null or empty collection means any
     *            format is acceptable
     */
    protected void filterNameIDAttributesByFormats(Collection<BaseAttribute<?>> attributes,
            Collection<String> acceptableFormats) {
        if (attributes.isEmpty() || acceptableFormats == null || acceptableFormats.isEmpty()) {
            return;
        }

        log.debug(
                "Filtering out potential name identifier attributes which do not support one of the following formats: {}",
                acceptableFormats);

        BaseAttribute<?> attribute;
        SAMLNameIdentifierEncoder nameIdEncoder;

        Iterator<BaseAttribute<?>> attributeItr = attributes.iterator();
        ATTRIBS: while (attributeItr.hasNext()) {
            attribute = attributeItr.next();
            for (AttributeEncoder encoder : attribute.getEncoders()) {
                if (encoder == null) {
                    continue;
                }

                if (encoder instanceof SAMLNameIdentifierEncoder) {
                    nameIdEncoder = (SAMLNameIdentifierEncoder) encoder;
                    if (acceptableFormats.contains(nameIdEncoder.getNameFormat())) {

                        log.debug("Retaining attribute {} which may be encoded as a name identifier of format {}",
                                attribute.getId(), nameIdEncoder.getNameFormat());
                        continue ATTRIBS;
                    }
                }
            }
            log.debug("Removing attribute {}, it can not be encoded in to a name identifier of an acceptable format",
                    attribute.getId());
            attributeItr.remove();
        }
    }

    /**
     * Gets the name identifier format required to be sent back to the relying party.
     * 
     * This implementation of this method returns null. Profile handler implementations should override this method if
     * an incoming request is capable of requiring a specific format.
     * 
     * @param requestContext current request context
     * 
     * @return the required name ID format or null if no specific format is required
     */
    protected String getRequiredNameIDFormat(BaseSAMLProfileRequestContext requestContext) {
        return null;
    }

    /**
     * Gets the name identifier formats to use when creating identifiers for the relying party.
     * 
     * @param requestContext current request context
     * 
     * @return list of formats, in preference order, that may be used with the relying party, or an empty list for no
     *         preference
     * 
     * @throws ProfileException thrown if there is a problem determining the name identifier format to use
     */
    protected List<String> getSupportedNameFormats(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        ArrayList<String> nameFormats = new ArrayList<String>();

        RoleDescriptor relyingPartyRole = requestContext.getPeerEntityRoleMetadata();
        if (relyingPartyRole != null) {
            List<String> relyingPartySupportedFormats = getEntitySupportedFormats(relyingPartyRole);
            if (relyingPartySupportedFormats != null && !relyingPartySupportedFormats.isEmpty()) {
                nameFormats.addAll(relyingPartySupportedFormats);
            }
        }

        // If metadata contains the unspecified name format this means that any format is acceptable
        if (nameFormats.contains(NameIdentifier.UNSPECIFIED)) {
            nameFormats.clear();
        }

        return nameFormats;
    }

    /**
     * Gets the list of name identifier formats supported for a given role.
     * 
     * @param role the role to get the list of supported name identifier formats
     * 
     * @return list of supported name identifier formats
     */
    protected List<String> getEntitySupportedFormats(RoleDescriptor role) {
        List<NameIDFormat> nameIDFormats = null;

        if (role instanceof SSODescriptor) {
            nameIDFormats = ((SSODescriptor) role).getNameIDFormats();
        } else if (role instanceof AuthnAuthorityDescriptor) {
            nameIDFormats = ((AuthnAuthorityDescriptor) role).getNameIDFormats();
        } else if (role instanceof PDPDescriptor) {
            nameIDFormats = ((PDPDescriptor) role).getNameIDFormats();
        } else if (role instanceof AttributeAuthorityDescriptor) {
            nameIDFormats = ((AttributeAuthorityDescriptor) role).getNameIDFormats();
        }

        ArrayList<String> supportedFormats = new ArrayList<String>();
        if (nameIDFormats != null) {
            for (NameIDFormat format : nameIDFormats) {
                supportedFormats.add(format.getFormat());
            }
        }

        return supportedFormats;
    }

    /**
     * Selects a name identifier attribute from a collection of attributes. If an ordered precedence of name identifier
     * formats is given then the attribute that produces a name identifier with the highest precedence is selected. If
     * no precedence is given, or no attribute support a format listed in the precedence list then the first attribute
     * which can be encoded in to name identifier is chosen.
     * 
     * @param <T> type name identifier
     * @param attributes attributes from which the identifier is selected, may not contain null values
     * @param nameIdEncoderType encoder to be used to encode the selected attribute
     * @param formatPrecedence precedence of name identifier formats, may not contain null values
     * 
     * @return the attribute to be encoded and the encoder to use
     */
    protected <T extends SAMLNameIdentifierEncoder> Pair<BaseAttribute, T> selectNameIDAttributeAndEncoder(
            Collection<BaseAttribute<?>> attributes, Class<T> nameIdEncoderType, String[] formatPrecedence) {
        if (attributes.isEmpty()) {
            return null;
        }
        
        log.debug("Selecting attribute to be encoded as a name identifier by encoder of type {}",
                nameIdEncoderType.getName());

        T nameIdEncoder;

        if (formatPrecedence != null) {
            log.debug("Attempting to select name identifier with highest precedence");
            for (String format : formatPrecedence) {
                for (BaseAttribute<?> attribute : attributes) {
                    for (AttributeEncoder encoder : attribute.getEncoders()) {
                        if (encoder == null) {
                            continue;
                        }

                        if (nameIdEncoderType.isInstance(encoder)) {
                            nameIdEncoder = (T) encoder;
                            if (DatatypeHelper.safeEquals(format, nameIdEncoder.getNameFormat())) {
                                return new Pair<BaseAttribute, T>(attribute, nameIdEncoder);
                            }
                        }
                    }
                }
                log.debug("No attribute can be encoded as a name identifier with format {}", format);
            }
            log.debug("No attribute can be encoded in to a name identifer with a format given in the precdence list.");
        }

        log.debug("Selecting the first attribute that can be encoded in to a name identifier");
        BaseAttribute<?> attribute = attributes.iterator().next();
        for (AttributeEncoder encoder : attribute.getEncoders()) {
            if (encoder == null) {
                continue;
            }

            if (nameIdEncoderType.isInstance(encoder)) {
                nameIdEncoder = (T) encoder;
                return new Pair<BaseAttribute, T>(attribute, nameIdEncoder);
            }
        }

        return null;
    }

    /**
     * Populates the request context with the information about the user if they have an existing session. Unless
     * overridden, {@link #populateRequestContext(BaseSAMLProfileRequestContext)} has already invoked
     * {@link #populateRelyingPartyInformation(BaseSAMLProfileRequestContext)},
     * {@link #populateAssertingPartyInformation(BaseSAMLProfileRequestContext)},
     * {@link #populateProfileInformation(BaseSAMLProfileRequestContext)}, and
     * {@link #populateSAMLMessageInformation(BaseSAMLProfileRequestContext)} have already been invoked and the
     * properties they provide are available in the request context.
     * 
     * This method should populate: user's session, user's principal name, and service authentication method
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is a problem populating the user's information
     */
    protected abstract void populateUserInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException;

    /**
     * Selects the appropriate endpoint for the relying party and stores it in the request context.
     * 
     * @param requestContext current request context
     * 
     * @return Endpoint selected from the information provided in the request context
     * 
     * @throws ProfileException thrown if there is a problem selecting a response endpoint
     */
    protected abstract Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) throws ProfileException;

    /**
     * Encodes the request's SAML response and writes it to the servlet response.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if no message encoder is registered for this profiles binding
     */
    protected void encodeResponse(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        try {
            SAMLMessageEncoder encoder = getOutboundMessageEncoder(requestContext);

            AbstractSAMLProfileConfiguration profileConfig = (AbstractSAMLProfileConfiguration) requestContext
                    .getProfileConfiguration();
            if (profileConfig != null) {
                if (isSignResponse(requestContext)) {
                    Credential signingCredential = profileConfig.getSigningCredential();
                    if (signingCredential == null) {
                        signingCredential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();
                    }

                    if (signingCredential == null) {
                        throw new ProfileException(
                                "Signing of responses is required but no signing credential is available");
                    }

                    if (signingCredential.getPrivateKey() == null) {
                        throw new ProfileException(
                                "Signing of response is required but signing credential does not have a private key");
                    }

                    requestContext.setOutboundSAMLMessageSigningCredential(signingCredential);
                }
            }

            log.debug("Encoding response to SAML request {} from relying party {}",
                    requestContext.getInboundSAMLMessageId(), requestContext.getInboundMessageIssuer());

            requestContext.setMessageEncoder(encoder);
            encoder.encode(requestContext);
        } catch (MessageEncodingException e) {
            throw new ProfileException("Unable to encode response to relying party: "
                    + requestContext.getInboundMessageIssuer(), e);
        }
    }

    /**
     * Determine whether responses should be signed.
     * 
     * @param requestContext the current request context
     * @return true if responses should be signed, false otherwise
     * @throws ProfileException if there is a problem determining whether responses should be signed
     */
    protected boolean isSignResponse(BaseSAMLProfileRequestContext requestContext) throws ProfileException {

        SAMLMessageEncoder encoder = getOutboundMessageEncoder(requestContext);

        AbstractSAMLProfileConfiguration profileConfig = (AbstractSAMLProfileConfiguration) requestContext
                .getProfileConfiguration();

        if (profileConfig != null) {
            try {
                return profileConfig.getSignResponses() == CryptoOperationRequirementLevel.always
                        || (profileConfig.getSignResponses() == CryptoOperationRequirementLevel.conditional && !encoder
                                .providesMessageIntegrity(requestContext));
            } catch (MessageEncodingException e) {
                log.error("Unable to determine if outbound encoding '{}' provides message integrity protection",
                        encoder.getBindingURI());
                throw new ProfileException("Unable to determine if outbound response should be signed");
            }
        } else {
            return false;
        }

    }

    /**
     * Get the outbound message encoder to use.
     * 
     * <p>
     * The default implementation uses the binding URI from the
     * {@link org.opensaml.common.binding.SAMLMessageContext#getPeerEntityEndpoint()} to lookup the encoder from the
     * supported message encoders defined in {@link #getMessageEncoders()}.
     * </p>
     * 
     * <p>
     * Subclasses may override to implement a different mechanism to determine the encoder to use, such as for example
     * cases where an active intermediary actor sits between this provider and the peer entity endpoint (e.g. the SAML 2
     * ECP case).
     * </p>
     * 
     * @param requestContext current request context
     * @return the message encoder to use
     * @throws ProfileException if the encoder to use can not be resolved based on the request context
     */
    protected SAMLMessageEncoder getOutboundMessageEncoder(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        SAMLMessageEncoder encoder = null;

        Endpoint endpoint = requestContext.getPeerEntityEndpoint();
        if (endpoint == null) {
            log.warn("No peer endpoint available for peer. Unable to send response.");
            throw new ProfileException("No peer endpoint available for peer. Unable to send response.");
        }

        if (endpoint != null) {
            encoder = getMessageEncoders().get(endpoint.getBinding());
            if (encoder == null) {
                log.error("No outbound message encoder configured for binding: {}", requestContext
                        .getPeerEntityEndpoint().getBinding());
                throw new ProfileException("No outbound message encoder configured for binding: "
                        + requestContext.getPeerEntityEndpoint().getBinding());
            }
        }
        return encoder;
    }

    /**
     * Get the inbound message decoder to use.
     * 
     * <p>
     * The default implementation uses the binding URI from {@link #getInboundBinding()} to lookup the decoder from the
     * supported message decoders defined in {@link #getMessageDecoders()}.
     * </p>
     * 
     * <p>
     * Subclasses may override to implement a different mechanism to determine the decoder to use.
     * </p>
     * 
     * @param requestContext current request context
     * @return the message decoder to use
     * @throws ProfileException if the decoder to use can not be resolved based on the request context
     */
    protected SAMLMessageDecoder getInboundMessageDecoder(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        SAMLMessageDecoder decoder = null;

        decoder = getMessageDecoders().get(getInboundBinding());
        if (decoder == null) {
            log.error("No inbound message decoder configured for binding: {}", getInboundBinding());
            throw new ProfileException("No inbound message decoder configured for binding: " + getInboundBinding());
        }
        return decoder;
    }

    /**
     * Writes an audit log entry indicating the successful response to the attribute request.
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

        getAduitLog().info(auditLogEntry.toString());
    }
}