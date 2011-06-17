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

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.Audience;
import org.opensaml.saml1.core.AudienceRestrictionCondition;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.RequestAbstractType;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.ResponseAbstractType;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.StatusMessage;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncodingException;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.SAML1NameIdentifierEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.CryptoOperationRequirementLevel;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/** Common implementation details for profile handlers. */
public abstract class AbstractSAML1ProfileHandler extends AbstractSAMLProfileHandler {

    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_11;

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(AbstractSAML1ProfileHandler.class);

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

    /** {@inheritDoc} */
    protected void populateRequestContext(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        BaseSAML1ProfileRequestContext saml1Request = (BaseSAML1ProfileRequestContext) requestContext;
        try {
            super.populateRequestContext(requestContext);
        } catch (ProfileException e) {
            if (saml1Request.getFailureStatus() == null) {
                saml1Request.setFailureStatus(buildStatus(StatusCode.REQUESTER, null, e.getMessage()));
            }
            throw e;
        }
    }

    /**
     * Populates the request context with the information about the user.
     * 
     * This method requires the the following request context properties to be populated: inbound message transport,
     * relying party ID
     * 
     * This methods populates the following request context properties: user's session, user's principal name, and
     * service authentication method
     * 
     * @param requestContext current request context
     */
    protected void populateUserInformation(BaseSAMLProfileRequestContext requestContext) {
        Session userSession = getUserSession(requestContext.getInboundMessageTransport());
        if (userSession == null) {
            NameIdentifier subject = (NameIdentifier) requestContext.getSubjectNameIdentifier();
            if (subject != null && subject.getNameIdentifier() != null) {
                userSession = getUserSession(subject.getNameIdentifier());
            }
        }

        if (userSession != null) {
            requestContext.setUserSession(userSession);
            requestContext.setPrincipalName(userSession.getPrincipalName());
            ServiceInformation serviceInfo = userSession.getServicesInformation().get(
                    requestContext.getInboundMessageIssuer());
            if (serviceInfo != null) {
                requestContext.setPrincipalAuthenticationMethod(serviceInfo.getAuthenticationMethod()
                        .getAuthenticationMethod());
            }
        }
    }

    /**
     * Checks that the SAML major version for a request is 1.
     * 
     * @param requestContext current request context containing the SAML message
     * 
     * @throws ProfileException thrown if the major version of the SAML request is not 1
     */
    protected void checkSamlVersion(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        SAMLObject samlObject = requestContext.getInboundSAMLMessage();

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
    protected Response buildResponse(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, List<Statement> statements)
            throws ProfileException {

        DateTime issueInstant = new DateTime();

        // create the SAML response and add the assertion
        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(issueInstant);
        populateStatusResponse(requestContext, samlResponse);

        // create the assertion and add the attribute statement
        Assertion assertion = null;
        if (statements != null && !statements.isEmpty()) {
            assertion = buildAssertion(requestContext, issueInstant);
            assertion.getStatements().addAll(statements);
            samlResponse.getAssertions().add(assertion);
            signAssertion(requestContext, assertion);
        }

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
    protected Assertion buildAssertion(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, DateTime issueInstant) {
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAMLVersion.VERSION_11);
        assertion.setIssuer(requestContext.getLocalEntityId());

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
    protected Conditions buildConditions(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, DateTime issueInstant) {
        AbstractSAML1ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(issueInstant.plus(profileConfig.getAssertionLifetime()));

        Collection<String> audiences;

        AudienceRestrictionCondition audienceRestriction = audienceRestrictionConditionBuilder.buildObject();
        conditions.getAudienceRestrictionConditions().add(audienceRestriction);

        Audience audience = audienceBuilder.buildObject();
        audience.setUri(requestContext.getInboundMessageIssuer());
        audienceRestriction.getAudiences().add(audience);

        // add other audience restrictions
        audiences = profileConfig.getAssertionAudiences();
        if (audiences != null && audiences.size() > 0) {
            for (String audienceUri : audiences) {
                audience = audienceBuilder.buildObject();
                audience.setUri(audienceUri);
                audienceRestriction.getAudiences().add(audience);
            }
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
    protected Subject buildSubject(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, String confirmationMethod)
            throws ProfileException {

        ConfirmationMethod method = confirmationMethodBuilder.buildObject();
        method.setConfirmationMethod(confirmationMethod);

        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.getConfirmationMethods().add(method);

        Subject subject = subjectBuilder.buildObject();
        subject.setSubjectConfirmation(subjectConfirmation);

        NameIdentifier nameID = buildNameId(requestContext);
        if (nameID != null) {
            subject.setNameIdentifier(nameID);
            requestContext.setSubjectNameIdentifier(nameID);
        }

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
    protected NameIdentifier buildNameId(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {
        Pair<BaseAttribute, SAML1NameIdentifierEncoder> nameIdAttributeAndEncoder = null;
        try {
            nameIdAttributeAndEncoder = selectNameIDAttributeAndEncoder(SAML1NameIdentifierEncoder.class,
                    requestContext);
        } catch (ProfileException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                    "Required NameIdentifier format not supported"));
            throw e;
        }

        if (nameIdAttributeAndEncoder == null) {
            return null;
        }

        BaseAttribute<?> nameIdAttribute = nameIdAttributeAndEncoder.getFirst();
        requestContext.setNameIdentifierAttribute(nameIdAttribute);
        SAML1NameIdentifierEncoder nameIdEncoder = nameIdAttributeAndEncoder.getSecond();

        try {
            log
                    .debug(
                            "Using attribute '{}' supporting name format '{}' to create the NameIdentifier for relying party '{}'",
                            new Object[] { nameIdAttribute.getId(), nameIdEncoder.getNameFormat(),
                                    requestContext.getInboundMessageIssuer(), });
            NameIdentifier nameId = nameIdEncoder.encode(nameIdAttribute);
            if (nameId.getNameQualifier() == null) {
                nameId.setNameQualifier(requestContext.getRelyingPartyConfiguration().getProviderId());
            }
            return nameId;
        } catch (AttributeEncodingException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Unable to encode NameIdentifier"));
            String msg = "Unable to encode NameIdentifier for relying party "
                    + requestContext.getInboundMessageIssuer();
            log.error(msg, e);
            throw new ProfileException(msg, e);
        }
    }

    /**
     * Constructs an SAML response message carrying a request error.
     * 
     * @param requestContext current request context containing the failure status
     * 
     * @return the constructed error response
     */
    protected Response buildErrorResponse(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) {
        Response samlResponse = responseBuilder.buildObject();
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
    protected void populateStatusResponse(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext,
            ResponseAbstractType response) {
        response.setID(getIdGenerator().generateIdentifier());

        SAMLObject samlMessage = requestContext.getInboundSAMLMessage();
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
    protected Status buildStatus(QName topLevelCode, QName secondLevelCode, String failureMessage) {
        Status status = statusBuilder.buildObject();

        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(topLevelCode);
        status.setStatusCode(statusCode);

        if (secondLevelCode != null) {
            StatusCode secondLevelStatusCode = statusCodeBuilder.buildObject();
            secondLevelStatusCode.setValue(secondLevelCode);
            statusCode.setStatusCode(secondLevelStatusCode);
        }

        if (failureMessage != null) {
            StatusMessage msg = statusMessageBuilder.buildObject();
            msg.setMessage(failureMessage);
            status.setStatusMessage(msg);
        }

        return status;
    }

    /**
     * Resolved the attributes for the principal.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is a problem resolving the attributes for the subject.
     */
    protected void resolveAttributes(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML1ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        try {
            log.debug("Resolving attributes for principal '{}' for SAML request from relying party '{}'",
                    requestContext.getPrincipalName(), requestContext.getInboundMessageIssuer());
            Map<String, BaseAttribute> principalAttributes = attributeAuthority.getAttributes(requestContext);

            requestContext.setAttributes(principalAttributes);
        } catch (AttributeRequestException e) {
            log
                    .warn(
                            "Error resolving attributes for principal '{}'.  No name identifier or attribute statement will be included in response",
                            requestContext.getPrincipalName());
        }
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
    protected AttributeStatement buildAttributeStatement(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext,
            String subjectConfMethod) throws ProfileException {

        if (requestContext.getAttributes() == null) {
            return null;
        }

        log.debug(
                "Creating attribute statement about principal '{}'in response to SAML request from relying party '{}'",
                requestContext.getPrincipalName(), requestContext.getInboundMessageIssuer());
        AbstractSAML1ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        try {
            AttributeStatement statment;
            if (requestContext.getInboundSAMLMessage() instanceof AttributeQuery) {
                statment = attributeAuthority.buildAttributeStatement((AttributeQuery) requestContext
                        .getInboundSAMLMessage(), requestContext.getAttributes().values());
            } else {
                statment = attributeAuthority.buildAttributeStatement(null, requestContext.getAttributes().values());
            }

            if (statment != null) {
                Subject statementSubject = buildSubject(requestContext, subjectConfMethod);
                statment.setSubject(statementSubject);
            }

            return statment;
        } catch (AttributeRequestException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error resolving attributes"));
            String msg = "Error encoding attributes for principal " + requestContext.getPrincipalName();
            log.error(msg, e);
            throw new ProfileException(msg, e);
        }
    }

    /**
     * Resolves the principal name of the subject of the request.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the principal name can not be resolved
     */
    protected void resolvePrincipal(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML1ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        log.debug("Resolving principal name for subject of SAML request from relying party '{}'", requestContext
                .getInboundMessageIssuer());

        try {
            String principal = attributeAuthority.getPrincipal(requestContext);
            requestContext.setPrincipalName(principal);
        } catch (AttributeRequestException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Error resolving principal"));
            String msg = "Error resolving principal name for SAML request from relying party '"
                    + requestContext.getInboundMessageIssuer() + "'. Cause: " + e.getMessage();
            log.warn(msg);
            throw new ProfileException(msg, e);
        }
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
    protected void signAssertion(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, Assertion assertion)
            throws ProfileException {
        log.debug("Determining if SAML assertion to relying party '{}' should be signed", requestContext
                .getInboundMessageIssuer());

        boolean signAssertion = isSignAssertion(requestContext);

        if (!signAssertion) {
            return;
        }

        AbstractSAML1ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        log.debug("Determining credential to use to sign assertion to relying party '{}'", requestContext
                .getInboundMessageIssuer());
        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();
        }

        if (signatureCredential == null) {
            String msg = "No signing credential is specified for relying party configuration "
                    + requestContext.getRelyingPartyConfiguration().getProviderId();
            log.warn(msg);
            throw new ProfileException(msg);
        }

        log.debug("Signing assertion to relying party '{}'", requestContext.getInboundMessageIssuer());
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signatureCredential);
        try {
            // TODO pull SecurityConfiguration from SAMLMessageContext? needs to be added
            // TODO how to pull what keyInfoGenName to use?
            SecurityHelper.prepareSignatureParams(signature, signatureCredential, null, null);
        } catch (SecurityException e) {
            String msg = "Error preparing signature for signing";
            log.error(msg);
            throw new ProfileException(msg, e);
        }

        assertion.setSignature(signature);

        Marshaller assertionMarshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
        try {
            assertionMarshaller.marshall(assertion);
            Signer.signObject(signature);
        } catch (MarshallingException e) {
            String errMsg = "Unable to marshall assertion for signing";
            log.error(errMsg, e);
            throw new ProfileException(errMsg, e);
        } catch (SignatureException e) {
            String msg = "Unable to sign assertion";
            log.error(msg, e);
            throw new ProfileException(msg, e);
        }
    }

    /**
     * Determine whether issued assertions should be signed.
     * 
     * @param requestContext the current request context
     * @return true if assertions should be signed, false otherwise
     * @throws ProfileException if there is a problem determining whether assertions should be signed
     */
    protected boolean isSignAssertion(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {

        SAMLMessageEncoder encoder = getOutboundMessageEncoder(requestContext);
        AbstractSAML1ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        try {
            boolean signAssertion = profileConfig.getSignAssertions() == CryptoOperationRequirementLevel.always
                    || (profileConfig.getSignAssertions() == CryptoOperationRequirementLevel.conditional && !encoder
                            .providesMessageIntegrity(requestContext));

            log.debug("IdP relying party configuration '{}' indicates to sign assertions: {}", requestContext
                    .getRelyingPartyConfiguration().getRelyingPartyId(), signAssertion);

            if (!signAssertion && requestContext.getPeerEntityRoleMetadata() instanceof SPSSODescriptor) {
                SPSSODescriptor ssoDescriptor = (SPSSODescriptor) requestContext.getPeerEntityRoleMetadata();
                if (ssoDescriptor.getWantAssertionsSigned() != null) {
                    signAssertion = ssoDescriptor.getWantAssertionsSigned().booleanValue();
                    log.debug("Entity metadata for relying party '{} 'indicates to sign assertions: {}", requestContext
                            .getInboundMessageIssuer(), signAssertion);
                }
            }

            return signAssertion;
        } catch (MessageEncodingException e) {
            log.error("Unable to determine if outbound encoding '{}' provides message integrity protection", encoder
                    .getBindingURI());
            throw new ProfileException("Unable to determine if outbound assertion should be signed");
        }
    }

    /**
     * Writes an audit log entry indicating the successful response to the attribute request.
     * 
     * @param context current request context
     */
    protected void writeAuditLogEntry(BaseSAMLProfileRequestContext context) {
        SAML1AuditLogEntry auditLogEntry = new SAML1AuditLogEntry();
        auditLogEntry.setSAMLResponse((Response) context.getOutboundSAMLMessage());
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
        
        if (context.getNameIdentifierAttribute() != null) {
            Object idValue = context.getNameIdentifierAttribute().getValues().iterator().next();
            if(idValue != null){
                auditLogEntry.setNameIdValue(idValue.toString());
            }
        }

        getAduitLog().info(auditLogEntry.toString());
    }

    /** SAML 1 specific audit log entry. */
    protected class SAML1AuditLogEntry extends AuditLogEntry {

        /** The response to the SAML 1 request. */
        private Response samlResponse;

        /**
         * Gets the response to the SAML 1 request.
         * 
         * @return the response to the SAML 1 request
         */
        public Response getSAMLResponse() {
            return samlResponse;
        }

        /**
         * Sets the response to the SAML 1 request.
         * 
         * @param response the response to the SAML 1 request
         */
        public void setSAMLResponse(Response response) {
            samlResponse = response;
        }

        /** {@inheritDoc} */
        public String toString() {
            StringBuilder entryString = new StringBuilder(super.toString());

            StringBuilder assertionIds = new StringBuilder();
            List<Assertion> assertions = samlResponse.getAssertions();
            if (assertions != null && !assertions.isEmpty()) {
                for (Assertion assertion : assertions) {
                    assertionIds.append(assertion.getID());
                    assertionIds.append(",");
                }
            }

            if (getNameIdValue() != null) {
                entryString.append(getNameIdValue());
            }
            entryString.append("|");

            entryString.append(assertionIds.toString());
            entryString.append("|");

            return entryString.toString();
        }
    }
}