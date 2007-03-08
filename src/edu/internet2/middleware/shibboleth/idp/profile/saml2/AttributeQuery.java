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
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BindingException;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.encryption.EncryptionException;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.FilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;

/**
 * SAML 2.0 Attribute Query profile handler.
 */
public class AttributeQuery extends AbstractProfileHandler {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AttributeQuery.class);

    /** {@inheritDoc} */
    public boolean processRequest(ServletRequest request, ServletResponse response) throws ServletException {
        if (log.isDebugEnabled()) {
            log.debug("begin processRequest");
        }

        // get message from the decoder
        org.opensaml.saml2.core.AttributeQuery message = null;
        try {
            message = (org.opensaml.saml2.core.AttributeQuery) decodeMessage(request);
        } catch (BindingException e) {
            log.error("Error decoding attribute query message", e);
            throw new ServletException("Error decoding attribute query message");
        }

        // get attribute statement from attribute authority
        AttributeAuthority aa = new AttributeAuthority();
        aa.setAttributeResolver(getAttributeResolver());
        aa.setFilteringEngine(getFilteringEngine());
        aa.setRelyingPartyConfiguration(getRelyingPartyConfiguration());
        aa.setSecurityPolicy(getDecoder().getSecurityPolicy());
        aa.setRequest(request);
        AttributeStatement statement = null;
        try {
            statement = aa.performAttributeQuery(message);
        } catch (AttributeResolutionException e) {
            log.error("Error resolving attributes", e);
            throw new ServletException("Error resolving attributes");
        } catch (FilteringException e) {
            log.error("Error filtering attributes", e);
            throw new ServletException("Error filtering attributes");
        }

        // construct attribute response
        Response samlResponse = null;
        try {
            samlResponse = buildResponse(message, request.getRemoteHost(), new DateTime(), statement);
        } catch (EncryptionException e) {
            log.error("Error encrypting SAML response", e);
            throw new ServletException("Error encrypting SAML response");
        }
        if (log.isDebugEnabled()) {
            log.debug("built saml2 response: " + samlResponse);
        }

        try {
            encodeResponse(samlResponse);
        } catch (BindingException e) {
            log.error("Error encoding attribute query response", e);
            throw new ServletException("Error encoding attribute query response");
        }

        return true;
    }

    /**
     * This builds the response for this SAML request.
     * 
     * @param message <code>AttributeQuery</code>
     * @param dest <code>String</code>
     * @param issueInstant <code>DateTime</code>
     * @param statement <code>AttributeStatement</code> of attributes
     * @return <code>Response</code>
     * @throws EncryptionException if an error occurs attempting to encrypt data
     */
    public Response buildResponse(org.opensaml.saml2.core.AttributeQuery message, String dest, DateTime issueInstant,
            AttributeStatement statement) throws EncryptionException {
        SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(
                Response.DEFAULT_ELEMENT_NAME);
        /*
         * required: samlp:Status, ID, Version, IssueInstant
         */
        Response response = responseBuilder.buildObject();
        response.setVersion(SAML_VERSION);
        response.setID(getIdGenerator().generateIdentifier());
        response.setInResponseTo(getDecoder().getSecurityPolicy().getIssuer().toString());
        response.setIssueInstant(issueInstant);
        response.setDestination(dest);

        response.setIssuer(buildIssuer());
        // TODO set consent
        /*
         * if (consent != null) { response.setConsent(consent); }
         */
        // TODO set extensions
        /*
         * if (extensions != null) { response.setExtensions(extensions); }
         */

        response.setStatus(buildStatus());
        if (getRelyingPartyConfiguration().encryptAssertion()) {
            response.getEncryptedAssertions().add(
                    getEncrypter().encrypt(buildAssertion(message.getSubject(), issueInstant, statement)));
        } else {
            response.getAssertions().add(buildAssertion(message.getSubject(), issueInstant, statement));
        }
        return response;
    }

    /**
     * This builds the status response for this SAML request.
     * 
     * @return <code>Status</code>
     */
    private Status buildStatus() {
        // build status
        SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(
                Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();

        // build status code
        SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory()
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        status.setStatusCode(statusCode);
        return status;
    }

    /**
     * This builds the assertion for this SAML request.
     * 
     * @param messageSubject <code>Subject</code>
     * @param issueInstant <code>DateTime</code>
     * @param statement <code>AttributeStatement</code> of attributes
     * @return <code>Assertion</code>
     * @throws EncryptionException if an error occurs attempting to encrypt data
     */
    private Assertion buildAssertion(Subject messageSubject, DateTime issueInstant, AttributeStatement statement)
            throws EncryptionException {
        // build assertions
        SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory().getBuilder(
                Assertion.DEFAULT_ELEMENT_NAME);
        /*
         * required: saml:Issuer, ID, Version, IssueInstant
         */
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAML_VERSION);
        assertion.setIssuer(buildIssuer());

        // build subject
        assertion.setSubject(buildSubject(messageSubject));
        // build conditions
        assertion.setConditions(buildConditions(issueInstant));
        // build advice
        assertion.setAdvice(buildAdvice());
        // add attribute statement
        assertion.getAttributeStatements().add(statement);
        return assertion;
    }

    /**
     * This builds the issuer response for this SAML request.
     * 
     * @return <code>Issuer</code>
     */
    private Issuer buildIssuer() {
        // build status
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) getBuilderFactory().getBuilder(
                Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(getRelyingPartyConfiguration().getProviderID());
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
        // build subject
        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(
                Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        if (getRelyingPartyConfiguration().encryptNameID()) {
            subject.setEncryptedID(getEncrypter().encrypt(messageSubject.getNameID()));
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
        SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory()
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(issueInstant);
        // TODO conditions.setNotOnOrAfter();
        // TODO add additional conditions : conditions.getConditions().add(Condition);
        // TODO what about AudienceRestriction, OneTimeUse, ProxyRestriction?
        return conditions;
    }

    /**
     * This builds the advice for this SAML request.
     * 
     * @return <code>Advice</code>
     */
    private Advice buildAdvice() {
        SAMLObjectBuilder<Advice> adviceBuilder = (SAMLObjectBuilder<Advice>) getBuilderFactory().getBuilder(
                Advice.DEFAULT_ELEMENT_NAME);
        Advice advice = adviceBuilder.buildObject();
        // advice.getAssertionIDReferences().add();
        // advice.getAssertionURIReferences().add();
        // advice.getAssertions().add();
        // advice.getEncryptedAssertions().add();
        // advice.addNamespace(namespace);
        return advice;
    }
}