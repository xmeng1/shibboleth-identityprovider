/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

import org.apache.log4j.Logger;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.ProxyRestriction;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;

import edu.internet2.middleware.shibboleth.common.attribute.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethAttributeRequestContext;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethSAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.saml2.AttributeQueryConfiguration;

/**
 * SAML 2.0 Attribute Query profile handler.
 */
public abstract class AbstractAttributeQuery extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AbstractAttributeQuery.class);

    /** For building response. */
    private SAMLObjectBuilder<Response> responseBuilder;

    /** For building status. */
    private SAMLObjectBuilder<Status> statusBuilder;

    /** For building statuscode. */
    private SAMLObjectBuilder<StatusCode> statusCodeBuilder;

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

    /** For building audience. */
    private SAMLObjectBuilder<Audience> audienceBuilder;

    /** For building advice. */
    private SAMLObjectBuilder<Advice> adviceBuilder;

    /** For building signature. */
    private XMLObjectBuilder<Signature> signatureBuilder;

    /** Attribute authority. */
    private SAML2AttributeAuthority attributeAuthority;

    /**
     * This creates a new attribute query.
     * 
     * @param ar <code>AttributeResolver</code>
     */
    public AbstractAttributeQuery(AttributeResolver<ShibbolethAttributeRequestContext> ar) {
        // instantiate attribute authority
        attributeAuthority = new ShibbolethSAML2AttributeAuthority(ar);

        // instantiate XML builders
        responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(
                StatusCode.DEFAULT_ELEMENT_NAME);
        issuerBuilder = (SAMLObjectBuilder<Issuer>) getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) getBuilderFactory().getBuilder(
                AudienceRestriction.DEFAULT_ELEMENT_NAME);
        audienceBuilder = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        adviceBuilder = (SAMLObjectBuilder<Advice>) getBuilderFactory().getBuilder(Advice.DEFAULT_ELEMENT_NAME);
        signatureBuilder = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
    }

    /**
     * This returns the <code>RelyingPartyConfiguration</code> for the supplied provider id.
     * 
     * @param providerId <code>String</code>
     * @return <code>RelyingPartyConfiguration</code>
     */
    protected RelyingPartyConfiguration getRelyingPartyConfiguration(String providerId) {
        return getRelyingPartyConfigurationManager().getRelyingPartyConfiguration(providerId);
    }

    /**
     * This returns the <code>AttributeQueryConfiguration</code> for the supplied provider id.
     * 
     * @param providerId <code>String</code>
     * @return <code>AttributeQueryConfiguration</code>
     */
    protected AttributeQueryConfiguration getAttributeQueryConfiguration(String providerId) {
        return (AttributeQueryConfiguration) getRelyingPartyConfiguration(providerId).getProfileConfigurations().get(
                AttributeQueryConfiguration.PROFILE_ID);
    }

    /**
     * This returns the <code>MetadataProvider</code> for this attribute query.
     * 
     * @return <code>MetadataProvider</code>
     */
    protected MetadataProvider getMetadataProvider() {
        return getRelyingPartyConfigurationManager().getMetadataProvider();
    }

    /**
     * This returns the <code>AttributeAuthority</code> for this attribute query.
     * 
     * @return <code>SAML2AttributeAuthority</code>
     */
    protected SAML2AttributeAuthority getAttributeAuthority() {
        return attributeAuthority;
    }

    /**
     * This builds the response for this SAML request.
     * 
     * @param responseContext <code>ProfileResponseContext</code>
     * @param issuer <code>String</code>
     * @param destination <code>String</code>
     * @return <code>Response</code>
     * @throws EncryptionException if an error occurs attempting to encrypt data
     */
    protected Response buildResponse(ProfileResponseContext responseContext, String issuer, String destination)
            throws EncryptionException {
        AttributeQueryConfiguration config = getAttributeQueryConfiguration(responseContext.getProviderId());

        /*
         * required: samlp:Status, ID, Version, IssueInstant
         */
        Response response = responseBuilder.buildObject();
        response.setVersion(SAML_VERSION);
        response.setID(getIdGenerator().generateIdentifier());
        response.setInResponseTo(issuer);
        response.setIssueInstant(responseContext.getIssueInstant());
        response.setDestination(destination);

        response.setIssuer(buildIssuer(responseContext.getProviderId()));

        /*
         * Will be hard coded in the future: if (consent != null) { response.setConsent(consent); }
         * 
         */

        /*
         * No extensions currently exist, will be hardcorded in the future: if (extensions != null) {
         * response.setExtensions(extensions); }
         * 
         */

        if (config.getSignAssertions()) {
            Signature s = buildSignature();
            s.setSigningKey(config.getSigningCredential().getPrivateKey());
            if (config.getEncryptAssertion()) {
                // TODO load encryption parameters
                Encrypter encrypter = null;
                Assertion a = buildAssertion(responseContext);
                a.setSignature(s);
                Signer.signObject(s);
                response.getEncryptedAssertions().add(encrypter.encrypt(a));
            } else {
                Assertion a = buildAssertion(responseContext);
                a.setSignature(s);
                Signer.signObject(s);
                response.getAssertions().add(a);
            }
        } else {
            if (config.getEncryptAssertion()) {
                // TODO load encryption parameters
                Encrypter encrypter = null;
                response.getEncryptedAssertions().add(encrypter.encrypt(buildAssertion(responseContext)));
            } else {
                response.getAssertions().add(buildAssertion(responseContext));
            }
        }
        response.setStatus(buildStatus(StatusCode.SUCCESS_URI));
        return response;
    }

    /**
     * This builds the status response for this SAML request.
     * 
     * @param statusCodeUri <code>String</code> to set
     * @return <code>Status</code>
     */
    private Status buildStatus(String statusCodeUri) {
        Status status = statusBuilder.buildObject();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeUri);
        status.setStatusCode(statusCode);
        return status;
    }

    /**
     * This builds the assertion for this SAML request.
     * 
     * @param responseContext <code>ProfileResponseContext</code>
     * @return <code>Assertion</code>
     * @throws EncryptionException if an error occurs attempting to encrypt data
     */
    private Assertion buildAssertion(ProfileResponseContext responseContext) throws EncryptionException {
        AttributeQueryConfiguration config = getAttributeQueryConfiguration(responseContext.getProviderId());

        /*
         * required: saml:Issuer, ID, Version, IssueInstant
         */
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(responseContext.getIssueInstant());
        assertion.setVersion(SAML_VERSION);
        assertion.setIssuer(buildIssuer(responseContext.getProviderId()));

        // build subject
        assertion.setSubject(buildSubject(responseContext.getMessage().getSubject(), config.getEncryptNameID()));
        // build conditions
        assertion.setConditions(buildConditions(responseContext));
        // build advice
        assertion.setAdvice(buildAdvice());
        // add attribute statement
        assertion.getAttributeStatements().add(responseContext.getAttributeStatement());
        return assertion;
    }

    /**
     * This builds the issuer response for this SAML request.
     * 
     * @param providerId <code>String</code>
     * @return <code>Issuer</code>
     */
    private Issuer buildIssuer(String providerId) {
        RelyingPartyConfiguration relyingPartyConfiguration = getRelyingPartyConfiguration(providerId);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(relyingPartyConfiguration.getProviderId());
        return issuer;
    }

    /**
     * This builds the subject for this SAML request.
     * 
     * @param messageSubject <code>Subject</code>
     * @param encryptNameId <code>boolean</code>
     * @return <code>Subject</code>
     * @throws EncryptionException if encryption of the name id fails
     */
    private Subject buildSubject(Subject messageSubject, boolean encryptNameId) throws EncryptionException {
        Subject subject = subjectBuilder.buildObject();
        if (encryptNameId) {
            // TODO load encryption parameters
            Encrypter encrypter = null;
            subject.setEncryptedID(encrypter.encrypt(messageSubject.getNameID()));
        } else {
            subject.setNameID(messageSubject.getNameID());
            // TODO when is subject.setBaseID(newBaseID) called, if ever?
        }
        return subject;
    }

    /**
     * This builds the conditions for this SAML request.
     * 
     * @param responseContext <code>ProfileResponseContext</code>
     * @return <code>Conditions</code>
     */
    private Conditions buildConditions(ProfileResponseContext responseContext) {
        AttributeQueryConfiguration config = getAttributeQueryConfiguration(responseContext.getProviderId());

        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(responseContext.getIssueInstant());
        conditions.setNotOnOrAfter(responseContext.getIssueInstant().plus(config.getAssertionLifetime()));

        // add audience restrictions
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
        for (String s : config.getAssertionAudiences()) {
            Audience audience = audienceBuilder.buildObject();
            audience.setAudienceURI(s);
            audienceRestriction.getAudiences().add(audience);
        }
        conditions.getAudienceRestrictions().add(audienceRestriction);

        // add proxy restrictions
        ProxyRestriction proxyRestriction = conditions.getProxyRestriction();
        for (String s : config.getProxyAudiences()) {
            Audience audience = audienceBuilder.buildObject();
            audience.setAudienceURI(s);
            proxyRestriction.getAudiences().add(audience);
        }
        proxyRestriction.setProxyCount(new Integer(config.getProxyCount()));

        /*
         * OneTimeUse and additional conditions not supported yet
         */

        return conditions;
    }

    /**
     * This builds the advice for this SAML request.
     * 
     * @return <code>Advice</code>
     */
    private Advice buildAdvice() {
        /*
         * Advice not supported at this time
         */
        Advice advice = adviceBuilder.buildObject();
        return advice;
    }

    /**
     * This builds a signature for this SAML request.
     * 
     * @return <code>Signature</code>
     */
    private Signature buildSignature() {
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        return signature;
    }
}