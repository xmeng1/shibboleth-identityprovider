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

import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import edu.internet2.middleware.shibboleth.common.attribute.Attribute;
import edu.internet2.middleware.shibboleth.common.attribute.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.SAML2AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.ResolutionContext;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractProfileHandler;

import org.joda.time.DateTime;

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;

/**
 * SAML 2.0 Attribute Query profile handler.
 */
public class AttributeQuery extends AbstractProfileHandler {

    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_20;
    
    
    /** {@inheritDoc} */
    public boolean processRequest(ServletRequest request, ServletResponse response) throws ServletException {
        // call decode method on decoder
        getDecoder().decode(request);
        // get SAMLMessage from the decoder
        final org.opensaml.saml2.core.AttributeQuery message =
            (org.opensaml.saml2.core.AttributeQuery) getDecoder().getSAMLMessage();
        
        // intersect requested attributes with released attributes
        final List<org.opensaml.saml2.core.Attribute> requestedAttributes = message.getAttributes();
        final Set<String> releasedAttributes = new HashSet<String>(requestedAttributes.size());
        for (org.opensaml.saml2.core.Attribute a: requestedAttributes) {
            releasedAttributes.add(a.getName());            
        }
        List<String> releaseableAttributes = getFilterEngine().getReleaseableAttributes(getDecoder().getIssuer());
        releasedAttributes.retainAll(releaseableAttributes);
        // TODO go to metadata for other attributes

        // create resolution context from the resolver, using nameid element from the attribute query
        ResolutionContext context = getAttributeResolver().createResolutionContext(
                message.getSubject().getNameID(), getDecoder().getIssuer(), request);
        // call Attribute resolver
        Set<Attribute> resolvedAttributes = getAttributeResolver().resolveAttributes(releasedAttributes, context);
        
        // construct attribute response
        List<org.opensaml.saml2.core.Attribute> encodedAttributes = new ArrayList<org.opensaml.saml2.core.Attribute>();
        for (Attribute a: resolvedAttributes) {
            for (AttributeEncoder<Attribute, org.opensaml.saml2.core.Attribute> e: a.getEncoders()) {
                if (e instanceof SAML2AttributeEncoder) {
                    // get encoder and call encode method
                    encodedAttributes.add(e.encode(a));
                    break;                
                }
            }
        }

        Response samlResponse = buildResponse(getDecoder().getIssuer(), new DateTime(), encodedAttributes);
        getEncoder().setSAMLMessage(response);
        getEncoder().encode();
        return true;
    }
    
    
    /**
     * This builds the response for this SAML request.
     * 
     *  @param issuer <code>String</code>
     *  @param issueInstant <code>DateTime</code>
     *  @param encodedAttributes <code>List</code> of attributes
     *  @return <code>Response</code>
     */
    private Response buildResponse(
            String issuer, DateTime issueInstant, List<org.opensaml.saml2.core.Attribute> encodedAttributes) {
        SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(
            Response.DEFAULT_ELEMENT_NAME);
        Response response = responseBuilder.buildObject();
        response.setVersion(SAML_VERSION);
        response.setID(getIdGenerator().generateIdentifier());
        response.setInResponseTo(issuer);
        response.setIssueInstant(issueInstant);

        //response.setDestination(String);
        //response.setConsent(String);
        //response.setIssuer(Issuer);
        //response.setExtensions(Extensions);
        
        response.setStatus(buildStatus());
        response.getAssertions().add(buildAssertion(issueInstant, encodedAttributes));        
    }
    

    /**
     * This builds the status response for this SAML request.
     * 
     *  @return <code>Status</code>
     */
    private Status buildStatus() {
        // build status
        SAMLObjectBuilder statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(
                Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();

        // build status code
        SAMLObjectBuilder statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(
                StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        status.setStatusCode(statusCode);
        return status;
    }
    
    
    /**
     * This builds the assertion for this SAML request.
     * 
     *  @param issueInstant <code>DateTime</code>
     *  @param encodedAttributes <code>List</code> of attributes
     *  @return <code>Assertion</code>
     */
    private Assertion buildAssertion(DateTime issueInstant, List<org.opensaml.saml2.core.Attribute> encodedAttributes) {
        // build assertions
        SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory().getBuilder(
                Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAML_VERSION);
        // TODO assertion.setIssuer();

        // build subject
        SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(
                Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        // TOTO subject.setNameID(NameID); <- comes from request
        assertion.setSubject(subject);

        // build conditions
        SAMLObjectBuilder conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(issueInstant);
        //TODO conditions.setNotOnOrAfter();
        //TODO add additional conditions : conditions.getConditions().add(Condition); 
        assertion.setConditions(conditions);

        // build attribute statement
        SAMLObjectBuilder statementBuilder = (SAMLObjectBuilder<AttributeStatement>) getBuilderFactory().getBuilder(
                AttributeStatement.DEFAULT_ELEMENT_NAME);
        AttributeStatement statement = statementBuilder.buildObject();
        statement.getAttributes().addAll(encodedAttributes);
        assertion.getAttributeStatements().add(statement);
        
        return assertion;
    }
}