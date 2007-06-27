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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.log.Level;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.Audience;
import org.opensaml.saml1.core.AudienceRestrictionCondition;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.RequestAbstractType;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.ResponseAbstractType;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.StatusMessage;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AuthnAuthorityDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncodingException;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethSAMLAttributeRequestContext;
import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/** Common implementation details for profile handlers. */
public abstract class AbstractSAML1ProfileHandler extends AbstractSAMLProfileHandler {

    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_11;

    /** Class logger. */
    private static Logger log = Logger.getLogger(AbstractSAML1ProfileHandler.class);

    /** Builder of Response objects. */
    private SAMLObjectBuilder<Response> responseBuilder;

    /** Builder of Assertion objects. */
    private SAMLObjectBuilder<Assertion> assertionBuilder;

    /** Builder of Conditions objects. */
    private SAMLObjectBuilder<Conditions> conditionsBuilder;

    /** Builder of AudienceRestrictionCondition objects. */
    private SAMLObjectBuilder<AudienceRestrictionCondition> audienceRestrictionConditionBuilder;

    /** Builder of AudienceRestrictionCondition objects. */
    private SAMLObjectBuilder<Audience> audienceBuilder;

    /** Builder of NameIdentifier objects. */
    private SAMLObjectBuilder<NameIdentifier> nameIdBuilder;

    /** Builder of SubjectConfirmation objects. */
    private SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder;

    /** Builder of ConfirmationMethod objects. */
    private SAMLObjectBuilder<ConfirmationMethod> confirmationMethodBuilder;

    /** Builder of Subject objects. */
    private SAMLObjectBuilder<Subject> subjectBuilder;

    /** Builder for Status objects. */
    private SAMLObjectBuilder<Status> statusBuilder;

    /** Builder for StatusCode objects. */
    private SAMLObjectBuilder<StatusCode> statusCodeBuilder;

    /** Builder for StatusMessage objects. */
    private SAMLObjectBuilder<StatusMessage> statusMessageBuilder;

    /** For building signature. */
    private XMLObjectBuilder<Signature> signatureBuilder;

    /**
     * Default constructor.
     */
    @SuppressWarnings("unchecked")
    public AbstractSAML1ProfileHandler() {
        super();
        responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        audienceRestrictionConditionBuilder = (SAMLObjectBuilder<AudienceRestrictionCondition>) getBuilderFactory()
                .getBuilder(AudienceRestrictionCondition.DEFAULT_ELEMENT_NAME);
        audienceBuilder = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        nameIdBuilder = (SAMLObjectBuilder<NameIdentifier>) getBuilderFactory().getBuilder(
                NameIdentifier.DEFAULT_ELEMENT_NAME);
        subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) getBuilderFactory().getBuilder(
                SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        confirmationMethodBuilder = (SAMLObjectBuilder<ConfirmationMethod>) getBuilderFactory().getBuilder(
                ConfirmationMethod.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(
                StatusCode.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) getBuilderFactory().getBuilder(
                StatusMessage.DEFAULT_ELEMENT_NAME);
        signatureBuilder = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Convenience method for getting the SAML 1 Response builder.
     * 
     * @return SAML 1 Response builder
     */
    public SAMLObjectBuilder<Response> getResponseBuilder() {
        return responseBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 Assertion builder.
     * 
     * @return SAML 1 Assertion builder
     */
    public SAMLObjectBuilder<Assertion> getAssertionBuilder() {
        return assertionBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 Conditions builder.
     * 
     * @return SAML 1 Conditions builder
     */
    public SAMLObjectBuilder<Conditions> getConditionsBuilder() {
        return conditionsBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 AudienceRestrictionCondition builder.
     * 
     * @return SAML 1 AudienceRestrictionCondition builder
     */
    public SAMLObjectBuilder<AudienceRestrictionCondition> getAudienceRestrictionConditionBuilder() {
        return audienceRestrictionConditionBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 Audience builder.
     * 
     * @return SAML 1 Audience builder
     */
    public SAMLObjectBuilder<Audience> getAudienceBuilder() {
        return audienceBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 NameIdentifier builder.
     * 
     * @return SAML 1 NameIdentifier builder
     */
    public SAMLObjectBuilder<NameIdentifier> getNameIdentifierBuilder() {
        return nameIdBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 SubjectConfirmation builder.
     * 
     * @return SAML 1 SubjectConfirmation builder
     */
    public SAMLObjectBuilder<SubjectConfirmation> getSubjectConfirmationBuilder() {
        return subjectConfirmationBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 ConfirmationMethod builder.
     * 
     * @return SAML 1 ConfirmationMethod builder
     */
    public SAMLObjectBuilder<ConfirmationMethod> getConfirmationMethodBuilder() {
        return confirmationMethodBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 Subject builder.
     * 
     * @return SAML 1 Subject builder
     */
    public SAMLObjectBuilder<Subject> getSubjectBuilder() {
        return subjectBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 Status builder.
     * 
     * @return SAML 1 Status builder
     */
    public SAMLObjectBuilder<Status> getStatusBuilder() {
        return statusBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 StatusCode builder.
     * 
     * @return SAML 2 StatusCode builder
     */
    public SAMLObjectBuilder<StatusCode> getStatusCodeBuilder() {
        return statusCodeBuilder;
    }

    /**
     * Convenience method for getting the SAML 1 StatusMessage builder.
     * 
     * @return SAML StatusMessage builder
     */
    public SAMLObjectBuilder<StatusMessage> getStatusMessageBuilder() {
        return statusMessageBuilder;
    }

    /**
     * Checks that the SAML major version for a request is 1.
     * 
     * @param requestContext current request context containing the SAML message
     * 
     * @throws ProfileException thrown if the major version of the SAML request is not 1
     */
    protected void checkSamlVersion(SAML1ProfileRequestContext requestContext) throws ProfileException {
        SAMLObject samlObject = requestContext.getSamlRequest();

        if (samlObject instanceof RequestAbstractType) {
            RequestAbstractType request = (RequestAbstractType) samlObject;
            if (request.getMajorVersion() < 1) {
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER, StatusCode.REQUEST_VERSION_TOO_LOW,
                        null));
                throw new ProfileException("SAML request major version too low");
            } else if (request.getMajorVersion() > 1) {
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER, StatusCode.REQUEST_VERSION_TOO_HIGH,
                        null));
                throw new ProfileException("SAML request major version too low");
            }
        }
    }

    /**
     * Builds a response to the attribute query within the request context.
     * 
     * @param requestContext current request context
     * @param statements the statements to include in the response
     * 
     * @return the built response
     * 
     * @throws ProfileException thrown if there is a problem creating the SAML response
     */
    protected Response buildResponse(SAML1ProfileRequestContext requestContext, List<Statement> statements)
            throws ProfileException {

        DateTime issueInstant = new DateTime();

        // create the assertion and add the attribute statement
        Assertion assertion = buildAssertion(requestContext, issueInstant);
        if (statements != null) {
            assertion.getStatements().addAll(statements);
        }

        // create the SAML response and add the assertion
        Response samlResponse = getResponseBuilder().buildObject();
        samlResponse.setIssueInstant(issueInstant);
        populateStatusResponse(requestContext, samlResponse);

        samlResponse.getAssertions().add(assertion);

        // sign the assertion if it should be signed
        signAssertion(requestContext, assertion);

        Status status = buildStatus(StatusCode.SUCCESS, null, null);
        samlResponse.setStatus(status);

        return samlResponse;
    }

    /**
     * Builds a basic assertion with its id, issue instant, SAML version, issuer, subject, and conditions populated.
     * 
     * @param requestContext current request context
     * @param issueInstant time to use as assertion issue instant
     * 
     * @return the built assertion
     */
    protected Assertion buildAssertion(SAML1ProfileRequestContext requestContext, DateTime issueInstant) {
        Assertion assertion = getAssertionBuilder().buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAMLVersion.VERSION_11);
        assertion.setIssuer(requestContext.getAssertingPartyId());

        Conditions conditions = buildConditions(requestContext, issueInstant);
        assertion.setConditions(conditions);

        return assertion;
    }

    /**
     * Builds a SAML assertion condition set. The following fields are set; not before, not on or after, audience
     * restrictions, and proxy restrictions.
     * 
     * @param requestContext current request context
     * @param issueInstant timestamp the assertion was created
     * 
     * @return constructed conditions
     */
    protected Conditions buildConditions(SAML1ProfileRequestContext requestContext, DateTime issueInstant) {
        AbstractSAML1ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        Conditions conditions = getConditionsBuilder().buildObject();
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(issueInstant.plus(profileConfig.getAssertionLifetime()));

        Collection<String> audiences;

        // add audience restrictions
        audiences = profileConfig.getAssertionAudiences();
        if (audiences != null && audiences.size() > 0) {
            AudienceRestrictionCondition audienceRestriction = getAudienceRestrictionConditionBuilder().buildObject();
            for (String audienceUri : audiences) {
                Audience audience = getAudienceBuilder().buildObject();
                audience.setUri(audienceUri);
                audienceRestriction.getAudiences().add(audience);
            }
            conditions.getAudienceRestrictionConditions().add(audienceRestriction);
        }

        return conditions;
    }

    /**
     * Builds the SAML subject for the user for the service provider.
     * 
     * @param requestContext current request context
     * @param confirmationMethod subject confirmation method used for the subject
     * 
     * @return SAML subject for the user for the service provider
     * 
     * @throws ProfileException thrown if a NameID can not be created either because there was a problem encoding the
     *             name ID attribute or because there are no supported name formats
     */
    protected Subject buildSubject(SAML1ProfileRequestContext requestContext, String confirmationMethod)
            throws ProfileException {
        NameIdentifier nameID = buildNameId(requestContext);
        requestContext.setSubjectNameID(nameID);

        ConfirmationMethod method = getConfirmationMethodBuilder().buildObject();
        method.setConfirmationMethod(confirmationMethod);

        SubjectConfirmation subjectConfirmation = getSubjectConfirmationBuilder().buildObject();
        subjectConfirmation.getConfirmationMethods().add(method);

        Subject subject = getSubjectBuilder().buildObject();
        subject.setNameIdentifier(nameID);
        subject.setSubjectConfirmation(subjectConfirmation);

        return subject;
    }

    /**
     * Builds a NameIdentifier appropriate for this request. NameIdentifier are built by inspecting the SAML request and
     * metadata, picking a name format that was requested by the relying party or is mutually supported by both the
     * relying party and asserting party as described in their metadata entries. Once a set of supported name formats is
     * determined the principals attributes are inspected for an attribute supported an attribute encoder whose category
     * is one of the supported name formats.
     * 
     * @param requestContext current request context
     * 
     * @return the NameIdentifier appropriate for this request
     * 
     * @throws ProfileException thrown if a NameIdentifier can not be created either because there was a problem
     *             encoding the name ID attribute or because there are no supported name formats
     */
    protected NameIdentifier buildNameId(SAML1ProfileRequestContext requestContext) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Building assertion NameIdentifier to relying party " + requestContext.getRelyingPartyId()
                    + " for principal " + requestContext.getPrincipalName());
        }
        Map<String, BaseAttribute> principalAttributes = requestContext.getPrincipalAttributes();
        List<String> supportedNameFormats = getNameFormats(requestContext);

        if (log.isDebugEnabled()) {
            log.debug("Supported name formats: " + supportedNameFormats);
        }

        if (principalAttributes != null && supportedNameFormats != null) {
            try {
                AttributeEncoder<NameIdentifier> nameIdEncoder = null;
                for (BaseAttribute attribute : principalAttributes.values()) {
                    for (String nameFormat : supportedNameFormats) {
                        nameIdEncoder = attribute.getEncoderByCategory(nameFormat);
                        if (nameIdEncoder != null) {
                            if (log.isDebugEnabled()) {
                                log.debug("Using attribute " + attribute.getId() + " suppoting name format "
                                        + nameFormat + " to create the NameIdentifier for principal "
                                        + requestContext.getPrincipalName());
                            }
                            return nameIdEncoder.encode(attribute);
                        }
                    }
                }
            } catch (AttributeEncodingException e) {
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                        "Unable to construct NameIdentifier"));
                throw new ProfileException("Unable to encode NameIdentifier attribute", e);
            }
        }

        requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Unable to construct NameID"));
        throw new ProfileException("No principal attributes support NameIdentifier construction");
    }

    /**
     * Gets the NameIdentifier format to use when creating NameIdentifiers for the relying party.
     * 
     * @param requestContext current request context
     * 
     * @return list of formats that may be used with the relying party
     * 
     * @throws ProfileException thrown if there is a problem determing the NameIdentifier format to use
     */
    protected List<String> getNameFormats(SAML1ProfileRequestContext requestContext) throws ProfileException {
        ArrayList<String> nameFormats = new ArrayList<String>();

        RoleDescriptor assertingPartyRole = requestContext.getAssertingPartyRoleMetadata();
        List<String> assertingPartySupportedFormats = getEntitySupportedFormats(assertingPartyRole);

        if (nameFormats.isEmpty()) {
            RoleDescriptor relyingPartyRole = requestContext.getRelyingPartyRoleMetadata();
            List<String> relyingPartySupportedFormats = getEntitySupportedFormats(relyingPartyRole);

            assertingPartySupportedFormats.retainAll(relyingPartySupportedFormats);
            nameFormats.addAll(assertingPartySupportedFormats);
        }
        if (nameFormats.isEmpty()) {
            nameFormats.add("urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified");
        }

        return nameFormats;
    }

    /**
     * Gets the list of NameIdentifier formats supported for a given role.
     * 
     * @param role the role to get the list of supported NameIdentifier formats
     * 
     * @return list of supported NameIdentifier formats
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
     * Constructs an SAML response message carrying a request error.
     * 
     * @param requestContext current request context containing the failure status
     * 
     * @return the constructed error response
     */
    protected Response buildErrorResponse(SAML1ProfileRequestContext requestContext) {
        Response samlResponse = getResponseBuilder().buildObject();
        samlResponse.setIssueInstant(new DateTime());
        populateStatusResponse(requestContext, samlResponse);

        samlResponse.setStatus(requestContext.getFailureStatus());

        return samlResponse;
    }

    /**
     * Populates the response's id, in response to, issue instant, version, and issuer properties.
     * 
     * @param requestContext current request context
     * @param response the response to populate
     */
    protected void populateStatusResponse(SAML1ProfileRequestContext requestContext, ResponseAbstractType response) {
        response.setID(getIdGenerator().generateIdentifier());

        SAMLObject samlMessage = requestContext.getSamlRequest();
        if (samlMessage != null && samlMessage instanceof RequestAbstractType) {
            response.setInResponseTo(((RequestAbstractType) samlMessage).getID());
        }
        response.setVersion(SAMLVersion.VERSION_11);
    }

    /**
     * Build a status message, with an optional second-level failure message.
     * 
     * @param topLevelCode top-level status code
     * @param secondLevelCode second-level status code
     * @param failureMessage An optional second-level failure message
     * 
     * @return a Status object.
     */
    protected Status buildStatus(String topLevelCode, String secondLevelCode, String failureMessage) {
        Status status = getStatusBuilder().buildObject();

        StatusCode statusCode = getStatusCodeBuilder().buildObject();
        statusCode.setValue(DatatypeHelper.safeTrimOrNullString(topLevelCode));
        status.setStatusCode(statusCode);

        if (secondLevelCode != null) {
            StatusCode secondLevelStatusCode = getStatusCodeBuilder().buildObject();
            secondLevelStatusCode.setValue(DatatypeHelper.safeTrimOrNullString(secondLevelCode));
            statusCode.setStatusCode(secondLevelStatusCode);
        }

        if (failureMessage != null) {
            StatusMessage msg = getStatusMessageBuilder().buildObject();
            msg.setMessage(failureMessage);
            status.setStatusMessage(msg);
        }

        return status;
    }

    /**
     * Executes a query for attributes and builds a SAML attribute statement from the results.
     * 
     * @param requestContext current request context
     * @param subjectConfMethod subject confirmation method
     * 
     * @return attribute statement resulting from the query
     * 
     * @throws ProfileException thrown if there is a problem making the query
     */
    protected AttributeStatement buildAttributeStatement(SAML1ProfileRequestContext requestContext,
            String subjectConfMethod) throws ProfileException {

        if (log.isDebugEnabled()) {
            log.debug("Creating attribute statement in response to SAML request from relying party "
                    + requestContext.getRelyingPartyId());
        }

        AbstractSAML1ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        try {
            if (log.isDebugEnabled()) {
                log.debug("Resolving attributes for principal " + requestContext.getPrincipalName()
                        + " of SAML request from relying party " + requestContext.getRelyingPartyId());
            }
            Map<String, BaseAttribute> principalAttributes = attributeAuthority
                    .getAttributes(buildAttributeRequestContext(requestContext));

            requestContext.setPrincipalAttributes(principalAttributes);

            AttributeStatement statment;
            if (requestContext.getSamlRequest() instanceof AttributeQuery) {
                statment = attributeAuthority.buildAttributeStatement((AttributeQuery) requestContext.getSamlRequest(),
                        principalAttributes.values());
            } else {
                statment = attributeAuthority.buildAttributeStatement(null, principalAttributes.values());
            }

            Subject statementSubject = buildSubject(requestContext, subjectConfMethod);
            statment.setSubject(statementSubject);

            return statment;
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes for SAML request from relying party "
                    + requestContext.getRelyingPartyId(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error resolving attributes"));
            throw new ProfileException("Error resolving attributes for SAML request from relying party "
                    + requestContext.getRelyingPartyId(), e);
        }
    }

    /**
     * Resolves the principal name of the subject of the request.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the principal name can not be resolved
     */
    protected void resolvePrincipal(SAML1ProfileRequestContext requestContext) throws ProfileException {
        AbstractSAML1ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        if (log.isDebugEnabled()) {
            log.debug("Resolving principal name for subject of SAML request from relying party "
                    + requestContext.getRelyingPartyId());
        }

        try {
            String principal = attributeAuthority.getPrincipal(buildAttributeRequestContext(requestContext));
            requestContext.setPrincipalName(principal);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes for SAML request from relying party "
                    + requestContext.getRelyingPartyId(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Error resolving principal"));
            throw new ProfileException("Error resolving attributes for SAML request from relying party "
                    + requestContext.getRelyingPartyId(), e);
        }
    }

    /**
     * Creates an attribute query context from the current profile request context.
     * 
     * @param requestContext current profile request
     * 
     * @return created query context
     */
    protected ShibbolethSAMLAttributeRequestContext<NameIdentifier, AttributeQuery> buildAttributeRequestContext(
            SAML1ProfileRequestContext requestContext) {

        ShibbolethSAMLAttributeRequestContext<NameIdentifier, AttributeQuery> queryContext;

        if (requestContext.getSamlRequest() instanceof Request) {
            Request samlRequest = (Request) requestContext.getSamlRequest();
            queryContext = new ShibbolethSAMLAttributeRequestContext<NameIdentifier, AttributeQuery>(
                    getMetadataProvider(), requestContext.getRelyingPartyConfiguration(),
                    samlRequest.getAttributeQuery());
        } else {
            queryContext = new ShibbolethSAMLAttributeRequestContext<NameIdentifier, AttributeQuery>(
                    getMetadataProvider(), requestContext.getRelyingPartyConfiguration(), null);
        }

        queryContext.setAttributeRequester(requestContext.getAssertingPartyId());
        queryContext.setPrincipalName(requestContext.getPrincipalName());
        queryContext.setProfileConfiguration(requestContext.getProfileConfiguration());
        queryContext.setRequest(requestContext.getProfileRequest());

        Session userSession = getSessionManager().getSession(getUserSessionId(requestContext.getProfileRequest()));
        if (userSession != null) {
            queryContext.setUserSession(userSession);
            ServiceInformation serviceInfo = userSession.getServicesInformation().get(
                    requestContext.getRelyingPartyId());
            if (serviceInfo != null) {
                String principalAuthenticationMethod = serviceInfo.getAuthenticationMethod().getAuthenticationMethod();

                requestContext.setPrincipalAuthenticationMethod(principalAuthenticationMethod);
                queryContext.setPrincipalAuthenticationMethod(principalAuthenticationMethod);
            }
        }

        return queryContext;
    }

    /**
     * Signs the given assertion if either the current profile configuration or the relying party configuration contains
     * signing credentials.
     * 
     * @param requestContext current request context
     * @param assertion assertion to sign
     * 
     * @throws ProfileException thrown if the metadata can not be located for the relying party or, if signing is
     *             required, if a signing credential is not configured
     */
    protected void signAssertion(SAML1ProfileRequestContext requestContext, Assertion assertion)
            throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Determining if SAML assertion to relying party " + requestContext.getRelyingPartyId()
                    + " should be signed");
        }

        boolean signAssertion = false;

        RoleDescriptor relyingPartyRole = requestContext.getRelyingPartyRoleMetadata();
        AbstractSAML1ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        if (relyingPartyRole instanceof SPSSODescriptor) {
            SPSSODescriptor ssoDescriptor = (SPSSODescriptor) relyingPartyRole;
            if (ssoDescriptor.getWantAssertionsSigned() != null) {
                signAssertion = ssoDescriptor.getWantAssertionsSigned().booleanValue();
                if (log.isDebugEnabled()) {
                    log.debug("Entity metadata for relying party " + requestContext.getRelyingPartyId()
                            + " indicates to sign assertions: " + signAssertion);
                }
            }
        } else if (profileConfig.getSignAssertions()) {
            signAssertion = true;
            log.debug("IdP relying party configuration "
                    + requestContext.getRelyingPartyConfiguration().getRelyingPartyId()
                    + " indicates to sign assertions: " + signAssertion);
        }

        if (!signAssertion) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Determining signing credntial for assertion to relying party "
                    + requestContext.getRelyingPartyId());
        }
        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();
        }

        if (signatureCredential == null) {
            throw new ProfileException("No signing credential is specified for relying party configuration "
                    + requestContext.getRelyingPartyConfiguration().getProviderId()
                    + " or it's SAML2 attribute query profile configuration");
        }

        if (log.isDebugEnabled()) {
            log.debug("Signing assertion to relying party " + requestContext.getRelyingPartyId());
        }
        SAMLObjectContentReference contentRef = new SAMLObjectContentReference(assertion);
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.getContentReferences().add(contentRef);
        assertion.setSignature(signature);

        Signer.signObject(signature);
    }

    /**
     * Writes an aduit log entry indicating the successful response to the attribute request.
     * 
     * @param context current request context
     */
    protected void writeAuditLogEntry(SAML1ProfileRequestContext context) {
        AuditLogEntry auditLogEntry = new AuditLogEntry();
        auditLogEntry.setMessageProfile(getProfileId());
        auditLogEntry.setPrincipalAuthenticationMethod(context.getPrincipalAuthenticationMethod());
        auditLogEntry.setPrincipalName(context.getPrincipalName());
        auditLogEntry.setAssertingPartyId(context.getAssertingPartyId());
        auditLogEntry.setRelyingPartyId(context.getRelyingPartyId());
        auditLogEntry.setRequestBinding(context.getMessageDecoder().getBindingURI());
        auditLogEntry.setRequestId(null);
        auditLogEntry.setResponseBinding(context.getMessageEncoder().getBindingURI());
        auditLogEntry.setResponseId(context.getSamlResponse().getID());
        getAduitLog().log(Level.CRITICAL, auditLogEntry);
    }

    /**
     * Contextual object used to accumlate information as profile requests are being processed.
     * 
     * @param <RequestType> type of SAML 1 request
     * @param <ResponseType> type of SAML 1 response
     * @param <ProfileConfigurationType> configuration type for this profile
     */
    protected class SAML1ProfileRequestContext<RequestType extends RequestAbstractType, ResponseType extends ResponseAbstractType, ProfileConfigurationType extends AbstractSAML1ProfileConfiguration>
            extends SAMLProfileRequestContext {

        /** SAML request message. */
        private RequestType samlRequest;

        /** SAML response message. */
        private ResponseType samlResponse;

        /** Request profile configuration. */
        private ProfileConfigurationType profileConfiguration;

        /** The NameIdentifier of the subject of this request. */
        private NameIdentifier subjectNameIdentifier;

        /** The request failure status. */
        private Status failureStatus;

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public SAML1ProfileRequestContext(ProfileRequest<ServletRequest> request,
                ProfileResponse<ServletResponse> response) {
            super(request, response);
        }

        /**
         * Gets the NameIdentifier of the subject of this request.
         * 
         * @return NameIdentifier of the subject of this request
         */
        public NameIdentifier getSubjectNameID() {
            return subjectNameIdentifier;
        }

        /**
         * Sets the NameIdentifier of the subject of this request.
         * 
         * @param id NameIdentifier of the subject of this request
         */
        public void setSubjectNameID(NameIdentifier id) {
            subjectNameIdentifier = id;
        }

        /**
         * Gets the profile configuration for this request.
         * 
         * @return profile configuration for this request
         */
        public ProfileConfigurationType getProfileConfiguration() {
            return profileConfiguration;
        }

        /**
         * Sets the profile configuration for this request.
         * 
         * @param configuration profile configuration for this request
         */
        public void setProfileConfiguration(ProfileConfigurationType configuration) {
            profileConfiguration = configuration;
        }

        /**
         * Gets the SAML request message.
         * 
         * @return SAML request message
         */
        public RequestType getSamlRequest() {
            return samlRequest;
        }

        /**
         * Sets the SAML request message.
         * 
         * @param request SAML request message
         */
        public void setSamlRequest(RequestType request) {
            samlRequest = request;
        }

        /**
         * Gets the SAML response message.
         * 
         * @return SAML response message
         */
        public ResponseType getSamlResponse() {
            return samlResponse;
        }

        /**
         * Sets the SAML response message.
         * 
         * @param response SAML response message
         */
        public void setSamlResponse(ResponseType response) {
            samlResponse = response;
        }

        /**
         * Gets the status reflecting a request failure.
         * 
         * @return status reflecting a request failure
         */
        public Status getFailureStatus() {
            return failureStatus;
        }

        /**
         * Sets the status reflecting a request failure.
         * 
         * @param status status reflecting a request failure
         */
        public void setFailureStatus(Status status) {
            failureStatus = status;
        }
    }
}