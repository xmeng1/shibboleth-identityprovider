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

import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.encoding.MessageEncoder;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.StatusMessage;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;


/**
 * Common implementation details for profile handlers.
 */
public abstract class AbstractSAML1ProfileHandler extends AbstractSAMLProfileHandler {
    
    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_11;
    
    /** Class logger. */
    private static Logger log = Logger.getLogger(AbstractSAML1ProfileHandler.class);
    
    /** For generating random ids. */
    private SecureRandomIdentifierGenerator idGenerator;
    
    /** Builder for Status objects. */
    protected SAMLObjectBuilder<Status> statusBuilder;
    
    /** Builder for StatusCode objects. */
    protected SAMLObjectBuilder<StatusCode> statusCodeBuilder;
    
    /** Builder for StatusMessage objects. */
    protected SAMLObjectBuilder<StatusMessage> statusMessageBuilder;
    
    /** For building signature. */
    private XMLObjectBuilder<Signature> signatureBuilder;
    
    /**
     * Default constructor.
     */
    public AbstractSAML1ProfileHandler() {
        idGenerator = new SecureRandomIdentifierGenerator();
        
        statusBuilder        = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder    = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) getBuilderFactory().getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
        signatureBuilder     = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
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
     * Build a SAML 1 Status element.
     *
     * @param statusCode The status code - see oasis-sstc-saml-core-1.1, section 3.4.3.1.
     * @param statusMessage The status message, or <code>null</code> if none is to be set.
     *
     * @return The Status object, or <code>null</code> on error.
     */
    protected Status buildStatus(String statusCode, String statusMessage) {
        
        if (statusCode == null || statusCode.equals("")) {
            return null;
        }
        
        Status status = statusBuilder.buildObject();
        StatusCode sc = statusCodeBuilder.buildObject();
        sc.setValue(statusCode);
        status.setStatusCode(sc);
        
        if (statusMessage != null || !(statusMessage.equals(""))) {
            
            StatusMessage sm = statusMessageBuilder.buildObject();
            sm.setMessage(statusMessage);
            status.setStatusMessage(sm);
        }
        
        return status;
    }
    
    /**
     * Signs the given assertion if either the current profile configuration or the relying party configuration contains
     * signing credentials.
     *
     * @param assertion assertion to sign
     * @param rpConfig relying party configuration
     * @param profileConfig current profile configuration
     */
    protected void signAssertion(Assertion assertion, RelyingPartyConfiguration rpConfig,
            AbstractSAML1ProfileConfiguration profileConfig) {
        if (!profileConfig.getSignAssertions()) {
            return;
        }
        
        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = rpConfig.getDefaultSigningCredential();
        }
        
        if (signatureCredential == null) {
            return;
        }
        
        SAMLObjectContentReference contentRef = new SAMLObjectContentReference(assertion);
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.getContentReferences().add(contentRef);
        assertion.setSignature(signature);
        
        Signer.signObject(signature);
    }
    
    /**
     * Encode a SAML Response.
     * 
     * @param binding The SAML protocol binding to use.
     * @param profileResponse The Raw output stream to send the message to.
     * @param samlResponse The SAML Response to send.
     * @param relyingParty The relying party to send the message to.
     * @param roleDescriptor The role of the message sender.
     * @param endpoint The endpoint to which the message should be send.
     * 
     * @throws ProfileException On error.
     */
    protected void encodeResponse(String binding,final ProfileResponse<ServletResponse> profileResponse,
            final Response samlResponse, final RelyingPartyConfiguration relyingParty,
            final RoleDescriptor roleDescriptor, final Endpoint endpoint) throws ProfileException {
        
        MessageEncoder<ServletResponse> encoder = getMessageEncoderFactory().getMessageEncoder(binding);
        if (encoder == null) {
            log.error("No MessageEncoder registered for " + binding);
            throw new ProfileException("No MessageEncoder registered for " + binding);
        }
        
        encoder.setResponse(profileResponse.getRawResponse());
        encoder.setIssuer(relyingParty.getProviderId());
        encoder.setMetadataProvider(getRelyingPartyConfigurationManager().getMetadataProvider());
        encoder.setRelyingPartyRole(roleDescriptor);
        encoder.setSigningCredential(relyingParty.getDefaultSigningCredential());
        encoder.setSamlMessage(samlResponse);
        encoder.setRelyingPartyEndpoint(endpoint);
        
        try {
            encoder.encode();
        } catch (BindingException ex) {
            log.error("Unable to encode response the relying party: " + relyingParty.getRelyingPartyId(), ex);
            throw new ProfileException("Unable to encode response the relying party: "
                    + relyingParty.getRelyingPartyId(), ex);
        }
        
    }
}