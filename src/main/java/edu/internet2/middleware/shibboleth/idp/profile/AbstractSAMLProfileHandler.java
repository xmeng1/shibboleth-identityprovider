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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.binding.SAMLMessageContext;
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
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
     * This method requires the the following request context properties to be populated: peer entity ID
     * 
     * This methods populates the following request context properties: peer entity metadata, relying party
     * configuration
     * 
     * @param requestContext current request context
     * @throws ProfileException thrown if there is a problem looking up the relying party's metadata
     */
    protected void populateRelyingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        MetadataProvider metadataProvider = requestContext.getMetadataProvider();
        String relyingPartyId = requestContext.getInboundMessageIssuer();

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
     * Gets the name identifier formats to use when creating identifiers for the relying party.
     * 
     * @param requestContext current request context
     * 
     * @return list of formats that may be used with the relying party, or an empty list for no preference
     * 
     * @throws ProfileException thrown if there is a problem determining the name identifier format to use
     */
    protected List<String> getNameFormats(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        ArrayList<String> nameFormats = new ArrayList<String>();

        RoleDescriptor relyingPartyRole = requestContext.getPeerEntityRoleMetadata();
        if (relyingPartyRole != null) {
            List<String> relyingPartySupportedFormats = getEntitySupportedFormats(relyingPartyRole);
            if (relyingPartySupportedFormats != null && !relyingPartySupportedFormats.isEmpty()) {
                nameFormats.addAll(relyingPartySupportedFormats);
            }
        }

        // If metadata contains the unspecified name format this means that any are supported
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
                if (profileConfig.getSignResponses() == CryptoOperationRequirementLevel.always
                        || (profileConfig.getSignResponses() == CryptoOperationRequirementLevel.conditional && !encoder
                                .providesMessageIntegrity(requestContext))) {
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

            log.debug("Encoding response to SAML request {} from relying party {}", requestContext
                    .getInboundSAMLMessageId(), requestContext.getInboundMessageIssuer());

            requestContext.setMessageEncoder(encoder);
            encoder.encode(requestContext);
        } catch (MessageEncodingException e) {
            throw new ProfileException("Unable to encode response to relying party: "
                    + requestContext.getInboundMessageIssuer(), e);
        }
    }

    /**
     * Get the outbound message encoder to use.
     * 
     * <p>The default implementation uses the binding URI from the 
     * {@link SAMLMessageContext#getPeerEntityEndpoint()} to lookup
     * the encoder from the supported message encoders defined in {@link #getMessageEncoders()}.
     * </p>
     * 
     * <p>
     * Subclasses may override to implement a different mechanism to determine the 
     * encoder to use, such as for example cases where an active intermediary actor
     * sits between this provider and the peer entity endpoint (e.g. the SAML 2 ECP case).
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