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

import javax.servlet.ServletException;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BindingException;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
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
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.security.credential.Credential;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethAttributeRequestContext;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethSAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.saml2.AttributeQueryConfiguration;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;

/**
 * SAML 2.0 Attribute Query profile handler.
 */
public class AttributeQuery extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AttributeQuery.class);

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

    /** Provider id. */
    private String providerId;

    /** Attribute authority. */
    private SAML2AttributeAuthority attributeAuthority;

    /** Attribute query configuration. */
    private AttributeQueryConfiguration config;

    /**
     * This creates a new attribute query.
     * 
     * @param ar <code>AttributeResolver</code>
     */
    public AttributeQuery(AttributeResolver<ShibbolethAttributeRequestContext> ar) {
        // instantiate configuration
        config = new AttributeQueryConfiguration();
        providerId = config.getProfileId();

        // instantiate attribute authority
        attributeAuthority = new ShibbolethSAML2AttributeAuthority(ar);

        // instantiate XML builders
        responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(
                StatusCode.DEFAULT_ELEMENT_NAME);
        assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        issuerBuilder = (SAMLObjectBuilder<Issuer>) getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) getBuilderFactory().getBuilder(
                AudienceRestriction.DEFAULT_ELEMENT_NAME);
        audienceBuilder = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        adviceBuilder = (SAMLObjectBuilder<Advice>) getBuilderFactory().getBuilder(Advice.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public boolean processRequest(ProfileRequest request, ProfileResponse response) throws ServletException {
        if (log.isDebugEnabled()) {
            log.debug("begin processRequest");
        }

        // get message from the decoder
        org.opensaml.saml2.core.AttributeQuery message = null;
        try {
            message = (org.opensaml.saml2.core.AttributeQuery) decodeMessage(request.getMessageDecoder(), request
                    .getRequest());
        } catch (BindingException e) {
            log.error("Error decoding attribute query message", e);
            throw new ServletException("Error decoding attribute query message");
        }

        // TODO get user data from the session
        ServiceInformation serviceInformation = null;
        String principalName = serviceInformation.getSubjectNameID().getSPProvidedID();
        String authenticationMethod = serviceInformation.getAuthenticationMethod().getAuthenticationMethod();

        // create attribute request for the attribute authority
        ShibbolethAttributeRequestContext requestContext = null;
        try {
            MetadataProvider metadataProvider = getRelyingPartyManager().getMetadataProvider();
            RelyingPartyConfiguration relyingPartyConfiguration = getRelyingPartyManager()
                    .getRelyingPartyConfiguration(providerId);
            requestContext = new ShibbolethAttributeRequestContext(metadataProvider, relyingPartyConfiguration);
            requestContext.setPrincipalName(principalName);
            requestContext.setPrincipalAuthenticationMethod(authenticationMethod);
            requestContext.setRequest(request.getRequest());
        } catch (MetadataProviderException e) {
            log.error("Error creating ShibbolethAttributeRequestContext", e);
            throw new ServletException("Error retrieving metadata", e);
        }

        // resolve attributes with the attribute authority
        AttributeStatement statement = null;
        try {
            statement = attributeAuthority.performAttributeQuery(requestContext);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes", e);
            throw new ServletException("Error resolving attributes", e);
        }

        // construct attribute response
        Response samlResponse = null;
        try {
            ProfileResponseContext profileResponse = new ProfileResponseContext(request, message);
            profileResponse.setAttributeStatement(statement);
            samlResponse = buildResponse(profileResponse);
        } catch (EncryptionException e) {
            log.error("Error encrypting SAML response", e);
            throw new ServletException("Error encrypting SAML response", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("built saml2 response: " + samlResponse);
        }

        // encode response
        try {
            encodeResponse(response.getMessageEncoder(), samlResponse);
        } catch (BindingException e) {
            log.error("Error encoding attribute query response", e);
            throw new ServletException("Error encoding attribute query response", e);
        }

        return true;
    }

    /**
     * This builds the response for this SAML request.
     * 
     * @param responseContext <code>ProfileResponseContext</code>
     * @return <code>Response</code>
     * @throws EncryptionException if an error occurs attempting to encrypt data
     */
    private Response buildResponse(ProfileResponseContext responseContext) throws EncryptionException {
        /*
         * required: samlp:Status, ID, Version, IssueInstant
         */
        Response response = responseBuilder.buildObject();
        response.setVersion(SAML_VERSION);
        response.setID(getIdGenerator().generateIdentifier());
        response.setInResponseTo(responseContext.getRequest().getMessageDecoder().getSecurityPolicy().getIssuer()
                .toString());
        response.setIssueInstant(responseContext.getIssueInstant());
        response.setDestination(responseContext.getRequest().getRequest().getRemoteHost());

        response.setIssuer(buildIssuer());

        // TODO get consent configuration
        /*
         * if (consent != null) { response.setConsent(consent); }
         */

        // TODO get extension configuration
        /*
         * if (extensions != null) { response.setExtensions(extensions); }
         */

        if (config.getSignAssertions()) {
            // TODO sign assertion: Credential credential = config.getSigningCredential();
            if (config.getEncryptAssertion()) {
                // TODO load encryption parameters
                Encrypter encrypter = null;
                response.getEncryptedAssertions().add(encrypter.encrypt(buildAssertion(responseContext)));
            } else {
                response.getAssertions().add(buildAssertion(responseContext));
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
        /*
         * required: saml:Issuer, ID, Version, IssueInstant
         */
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(responseContext.getIssueInstant());
        assertion.setVersion(SAML_VERSION);
        assertion.setIssuer(buildIssuer());

        // build subject
        assertion.setSubject(buildSubject(responseContext.getMessage().getSubject()));
        // build conditions
        assertion.setConditions(buildConditions(responseContext.getIssueInstant()));
        // build advice
        assertion.setAdvice(buildAdvice());
        // add attribute statement
        assertion.getAttributeStatements().add(responseContext.getAttributeStatement());
        return assertion;
    }

    /**
     * This builds the issuer response for this SAML request.
     * 
     * @return <code>Issuer</code>
     */
    private Issuer buildIssuer() {
        RelyingPartyConfiguration relyingPartyConfiguration = getRelyingPartyManager().getRelyingPartyConfiguration(
                providerId);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(relyingPartyConfiguration.getProviderID());
        return issuer;
    }

    /**
     * This builds the subject for this SAML request.
     * 
     * @param messageSubject <code>Subject</code>
     * @return <code>Subject</code>
     * @throws EncryptionException if encryption of the name id fails
     */
    private Subject buildSubject(Subject messageSubject) throws EncryptionException {
        Subject subject = subjectBuilder.buildObject();
        if (config.getEncryptNameID()) {
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
     * @param issueInstant <code>DateTime</code>
     * @return <code>Conditions</code>
     */
    private Conditions buildConditions(DateTime issueInstant) {
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(issueInstant.plus(config.getAssertionLifetime()));

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

        // TODO add additional conditions : conditions.getConditions().add(Condition);
        // TODO what about OneTimeUse?
        return conditions;
    }

    /**
     * This builds the advice for this SAML request.
     * 
     * @return <code>Advice</code>
     */
    private Advice buildAdvice() {
        Advice advice = adviceBuilder.buildObject();
        // TODO set advice
        // advice.getAssertionIDReferences().add();
        // advice.getAssertionURIReferences().add();
        // advice.getAssertions().add();
        // advice.getEncryptedAssertions().add();
        // advice.addNamespace(namespace);
        return advice;
    }
}