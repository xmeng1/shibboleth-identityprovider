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

import java.util.Collection;

import org.joda.time.DateTime;

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SAMLObjectContentReference;

import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.ProxyRestriction;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.Subject;

import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.saml2.AbstractSAML2ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;

/**
 * Common implementation details for profile handlers.
 */
public abstract class AbstractSAML2ProfileHandler extends AbstractSAMLProfileHandler {
    
    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_20;
    
    /** URI for the SAML 2 protocol. */
    public static final String SAML20_PROTOCOL_URI = "urn:oasis:names:tc:SAML:2.0:protocol";
    
    /** For building response. */
    private SAMLObjectBuilder<Response> responseBuilder;
    
    /** For building status. */
    private SAMLObjectBuilder<Status> statusBuilder;
    
    /** For building statuscode. */
    private SAMLObjectBuilder<StatusCode> statusCodeBuilder;
    
    /** For building StatusMessages. */
    private SAMLObjectBuilder<StatusMessage> statusMessageBuilder;
    
    /** For building assertion. */
    private SAMLObjectBuilder<Assertion> assertionBuilder;
    
    /** For building issuer. */
    private SAMLObjectBuilder<Issuer> issuerBuilder;
    
    /** For building subject. */
    private SAMLObjectBuilder<Subject> subjectBuilder;
    
    /** For building conditions. */
    private SAMLObjectBuilder<Conditions> conditionsBuilder;
    
    /** For building audience restriction. */
    private SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder;
    
    /** For building proxy retrictions. */
    private SAMLObjectBuilder<ProxyRestriction> proxyRestrictionBuilder;
    
    /** For building audience. */
    private SAMLObjectBuilder<Audience> audienceBuilder;
    
    /** For building advice. */
    private SAMLObjectBuilder<Advice> adviceBuilder;
    
    /** For building signature. */
    private XMLObjectBuilder<Signature> signatureBuilder;
    
    /** Constructor. */
    @SuppressWarnings("unchecked")
    protected AbstractSAML2ProfileHandler() {
        
        super();
        
        responseBuilder            = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        statusBuilder              = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder          = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder       = (SAMLObjectBuilder<StatusMessage>) getBuilderFactory().getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
        issuerBuilder              = (SAMLObjectBuilder<Issuer>) getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        assertionBuilder           = (SAMLObjectBuilder<Assertion>) getBuilderFactory().getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        subjectBuilder             = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        conditionsBuilder          = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) getBuilderFactory().getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        proxyRestrictionBuilder    = (SAMLObjectBuilder<ProxyRestriction>) getBuilderFactory().getBuilder(ProxyRestriction.DEFAULT_ELEMENT_NAME);
        audienceBuilder            = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        adviceBuilder              = (SAMLObjectBuilder<Advice>) getBuilderFactory().getBuilder(Advice.DEFAULT_ELEMENT_NAME);
        signatureBuilder           = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
    }
    
    /**
     * Convenience method for getting the SAML 2 advice builder.
     *
     * @return SAML 2 advice builder
     */
    public SAMLObjectBuilder<Advice> getAdviceBuilder() {
        return adviceBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 assertion builder.
     *
     * @return SAML 2 assertion builder
     */
    public SAMLObjectBuilder<Assertion> getAssertionBuilder() {
        return assertionBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 audience builder.
     *
     * @return SAML 2 audience builder
     */
    public SAMLObjectBuilder<Audience> getAudienceBuilder() {
        return audienceBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 audience restriction builder.
     *
     * @return SAML 2 audience restriction builder
     */
    public SAMLObjectBuilder<AudienceRestriction> getAudienceRestrictionBuilder() {
        return audienceRestrictionBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 conditions builder.
     *
     * @return SAML 2 conditions builder
     */
    public SAMLObjectBuilder<Conditions> getConditionsBuilder() {
        return conditionsBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 Issuer builder.
     *
     * @return SAML 2 Issuer builder
     */
    public SAMLObjectBuilder<Issuer> getIssuerBuilder() {
        return issuerBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 proxy restriction builder.
     *
     * @return SAML 2 proxy restriction builder
     */
    public SAMLObjectBuilder<ProxyRestriction> getProxyRestrictionBuilder() {
        return proxyRestrictionBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 response builder.
     *
     * @return SAML 2 response builder
     */
    public SAMLObjectBuilder<Response> getResponseBuilder() {
        return responseBuilder;
    }
    
    /**
     * Convenience method for getting the Signature builder.
     *
     * @return signature builder
     */
    public XMLObjectBuilder<Signature> getSignatureBuilder() {
        return signatureBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 status builder.
     *
     * @return SAML 2 status builder
     */
    public SAMLObjectBuilder<Status> getStatusBuilder() {
        return statusBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 status code builder.
     *
     * @return SAML 2 status code builder
     */
    public SAMLObjectBuilder<StatusCode> getStatusCodeBuilder() {
        return statusCodeBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 status message builder.
     *
     * @return SAML 2 status message builder
     */
    public SAMLObjectBuilder<StatusMessage> getStatusMessageBuilder() {
        return statusMessageBuilder;
    }
    
    /**
     * Convenience method for getting the SAML 2 subject builder.
     *
     * @return SAML 2 subject builder
     */
    public SAMLObjectBuilder<Subject> getSubjectBuilder() {
        return subjectBuilder;
    }
    
    /**
     * Populates the response's id, in response to, issue instant, version, and issuer properties.
     *
     * @param response the response to populate
     * @param issueInstant timestamp to use as the issue instant for the response
     * @param request the request that the response is for
     * @param rpConfig the relying party configuration for the request
     */
    protected void populateStatusResponse(StatusResponseType response, DateTime issueInstant,
            RequestAbstractType request, RelyingPartyConfiguration rpConfig) {
        
        response.setID(getIdGenerator().generateIdentifier());
        response.setInResponseTo(request.getID());
        response.setIssueInstant(issueInstant);
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssuer(buildEntityIssuer(rpConfig));
    }
    
    /**
     * Build a status message, with an optional second-level failure message.
     *
     * @param topLevelCode
     *            The top-level status code. Should be from saml-core-2.0-os,
     *            sec. 3.2.2.2
     * @param secondLevelCode
     *            An optional second-level failure code. Should be from
     *            saml-core-2.0-is, sec 3.2.2.2. If null, no second-level Status
     *            element will be set.
     * @param secondLevelFailureMessage
     *            An optional second-level failure message.
     *
     * @return a Status object.
     */
    protected Status buildStatus(String topLevelCode, String secondLevelCode,
            String secondLevelFailureMessage) {
        
        Status status = statusBuilder.buildObject();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        
        statusCode.setValue(DatatypeHelper.safeTrimOrNullString(topLevelCode));
        if (secondLevelCode != null) {
            StatusCode secondLevelStatusCode = statusCodeBuilder.buildObject();
            secondLevelStatusCode.setValue(DatatypeHelper.safeTrimOrNullString(secondLevelCode));
            statusCode.setStatusCode(secondLevelStatusCode);
        }
        
        if (secondLevelFailureMessage != null) {
            StatusMessage msg = statusMessageBuilder.buildObject();
            msg.setMessage(secondLevelFailureMessage);
            status.setStatusMessage(msg);
        }
        
        return status;
    }
    
    /**
     * Builds a basic assertion with its id, issue instant, SAML version, issuer, subject, and conditions populated.
     *
     * @param issueInstant time to use as assertion issue instant
     * @param rpConfig the relying party configuration
     * @param profileConfig current profile configuration
     *
     * @return the built assertion
     */
    protected Assertion buildAssertion(final DateTime issueInstant, final RelyingPartyConfiguration rpConfig,
            final AbstractSAML2ProfileConfiguration profileConfig) {
        
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(buildEntityIssuer(rpConfig));
        //TODO assertion.setSubject(buildSubject());
        
        Conditions conditions = buildConditions(issueInstant, profileConfig);
        assertion.setConditions(conditions);
        
        return assertion;
    }
    
    /**
     * Builds an entity type Issuer populated with the correct provider Id for this relying party configuration.
     *
     * @param rpConfig the relying party configuration
     *
     * @return the built Issuer
     */
    protected Issuer buildEntityIssuer(final RelyingPartyConfiguration rpConfig) {
        
        Issuer issuer = getIssuerBuilder().buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(rpConfig.getProviderId());
        
        return issuer;
    }
    
    /**
     * Builds the SAML subject for the user for the service provider.
     *
     * @return SAML subject for the user for the service provider
     *
     * @throws EncryptionException thrown if there is a problem encryption the subject's NameID
     */
    protected Subject buildSubject() throws EncryptionException {
        // TODO
        return null;
    }
    
    /**
     * Builds a SAML assertion condition set. The following fields are set; not before, not on or after, audience
     * restrictions, and proxy restrictions.
     *
     * @param issueInstant timestamp the assertion was created
     * @param profileConfig current profile configuration
     *
     * @return constructed conditions
     */
    protected Conditions buildConditions(final DateTime issueInstant, final AbstractSAML2ProfileConfiguration profileConfig) {
        
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(issueInstant.plus(profileConfig.getAssertionLifetime()));
        
        Collection<String> audiences;
        
        // add audience restrictions
        audiences = profileConfig.getAssertionAudiences();
        if (audiences != null && audiences.size() > 0) {
            AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
            for (String audienceUri : audiences) {
                Audience audience = audienceBuilder.buildObject();
                audience.setAudienceURI(audienceUri);
                audienceRestriction.getAudiences().add(audience);
            }
            conditions.getAudienceRestrictions().add(audienceRestriction);
        }
        
        // add proxy restrictions
        audiences = profileConfig.getProxyAudiences();
        if (audiences != null && audiences.size() > 0) {
            ProxyRestriction proxyRestriction = proxyRestrictionBuilder.buildObject();
            Audience audience;
            for (String audienceUri : audiences) {
                audience = audienceBuilder.buildObject();
                audience.setAudienceURI(audienceUri);
                proxyRestriction.getAudiences().add(audience);
            }
            
            proxyRestriction.setProxyCount(profileConfig.getProxyCount());
            conditions.getConditions().add(proxyRestriction);
        }
        
        return conditions;
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
            AbstractSAML2ProfileConfiguration profileConfig) {
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
    
    protected void signResponse(StatusResponseType response, RelyingPartyConfiguration rpConfig, AbstractSAML2ProfileConfiguration profileConfig){
        if (!profileConfig.getSignResponses()) {
            return;
        }
        
        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = rpConfig.getDefaultSigningCredential();
        }
        
        if (signatureCredential == null) {
            return;
        }
        
        SAMLObjectContentReference contentRef = new SAMLObjectContentReference(response);
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.getContentReferences().add(contentRef);
        response.setSignature(signature);
        
        Signer.signObject(signature);
    }
    
    // TODO encryption support
}