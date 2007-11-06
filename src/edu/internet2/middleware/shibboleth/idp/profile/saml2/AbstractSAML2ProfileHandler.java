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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.ProxyRestriction;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AuthnAuthorityDescriptor;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncodingException;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.SAML2NameIDAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AbstractSAML2ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;

/** Common implementation details for profile handlers. */
public abstract class AbstractSAML2ProfileHandler extends AbstractSAMLProfileHandler {

    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_20;

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(AbstractSAML2ProfileHandler.class);

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

    /** For building subject confirmation. */
    private SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder;

    /** For building subject confirmation data. */
    private SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder;

    /** For building conditions. */
    private SAMLObjectBuilder<Conditions> conditionsBuilder;

    /** For building audience restriction. */
    private SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder;

    /** For building proxy retrictions. */
    private SAMLObjectBuilder<ProxyRestriction> proxyRestrictionBuilder;

    /** For building audience. */
    private SAMLObjectBuilder<Audience> audienceBuilder;

    /** For building signature. */
    private XMLObjectBuilder<Signature> signatureBuilder;

    /** Constructor. */
    @SuppressWarnings("unchecked")
    protected AbstractSAML2ProfileHandler() {
        super();

        responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(
                StatusCode.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) getBuilderFactory().getBuilder(
                StatusMessage.DEFAULT_ELEMENT_NAME);
        issuerBuilder = (SAMLObjectBuilder<Issuer>) getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) getBuilderFactory().getBuilder(
                SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) getBuilderFactory().getBuilder(
                SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) getBuilderFactory().getBuilder(
                AudienceRestriction.DEFAULT_ELEMENT_NAME);
        proxyRestrictionBuilder = (SAMLObjectBuilder<ProxyRestriction>) getBuilderFactory().getBuilder(
                ProxyRestriction.DEFAULT_ELEMENT_NAME);
        audienceBuilder = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        signatureBuilder = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Checks that the SAML major version for a request is 2.
     * 
     * @param requestContext current request context containing the SAML message
     * 
     * @throws ProfileException thrown if the major version of the SAML request is not 2
     */
    protected void checkSamlVersion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        SAMLVersion version = requestContext.getInboundSAMLMessage().getVersion();
        if (version.getMajorVersion() < 2) {
            requestContext.setFailureStatus(buildStatus(StatusCode.VERSION_MISMATCH_URI,
                    StatusCode.REQUEST_VERSION_TOO_LOW_URI, null));
            throw new ProfileException("SAML request version too low");
        } else if (version.getMajorVersion() > 2) {
            requestContext.setFailureStatus(buildStatus(StatusCode.VERSION_MISMATCH_URI,
                    StatusCode.REQUEST_VERSION_TOO_HIGH_URI, null));
            throw new ProfileException("SAML request version too high");
        }
    }

    /**
     * Builds a response to the attribute query within the request context.
     * 
     * @param requestContext current request context
     * @param subjectConfirmationMethod confirmation method used for the subject
     * @param statements the statements to include in the response
     * 
     * @return the built response
     * 
     * @throws ProfileException thrown if there is a problem creating the SAML response
     */
    protected Response buildResponse(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext,
            String subjectConfirmationMethod, List<Statement> statements) throws ProfileException {

        DateTime issueInstant = new DateTime();

        Subject subject = buildSubject(requestContext, subjectConfirmationMethod, issueInstant);

        // create the assertion and add the attribute statement
        Assertion assertion = buildAssertion(requestContext, issueInstant);
        assertion.setSubject(subject);
        if (statements != null) {
            assertion.getStatements().addAll(statements);
        }

        // create the SAML response and add the assertion
        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(issueInstant);
        populateStatusResponse(requestContext, samlResponse);

        samlResponse.getAssertions().add(assertion);

        // sign the assertion if it should be signed
        signAssertion(requestContext, assertion);

        Status status = buildStatus(StatusCode.SUCCESS_URI, null, null);
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
    protected Assertion buildAssertion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, DateTime issueInstant) {
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(buildEntityIssuer(requestContext));

        Conditions conditions = buildConditions(requestContext, issueInstant);
        assertion.setConditions(conditions);

        return assertion;
    }

    /**
     * Creates an {@link Issuer} populated with information about the relying party.
     * 
     * @param requestContext current request context
     * 
     * @return the built issuer
     */
    protected Issuer buildEntityIssuer(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) {
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(requestContext.getLocalEntityId());

        return issuer;
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
    protected Conditions buildConditions(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, DateTime issueInstant) {
        AbstractSAML2ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

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
     * Populates the response's id, in response to, issue instant, version, and issuer properties.
     * 
     * @param requestContext current request context
     * @param response the response to populate
     */
    protected void populateStatusResponse(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext,
            StatusResponseType response) {
        response.setID(getIdGenerator().generateIdentifier());
        if (requestContext.getInboundSAMLMessage() != null) {
            response.setInResponseTo(requestContext.getInboundSAMLMessageId());
        }
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssuer(buildEntityIssuer(requestContext));
    }

    /**
     * Resolves the attributes for the principal.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is a problem resolved attributes
     */
    protected void resolveAttributes(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML2ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        try {
            log.debug("Resolving attributes for principal {} of SAML request from relying party {}", requestContext
                    .getPrincipalName(), requestContext.getInboundMessageIssuer());
            Map<String, BaseAttribute> principalAttributes = attributeAuthority.getAttributes(requestContext);

            requestContext.setAttributes(principalAttributes);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes for SAML request " + requestContext.getInboundSAMLMessageId()
                    + " from relying party " + requestContext.getInboundMessageIssuer(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Error resolving attributes"));
            throw new ProfileException("Error resolving attributes for SAML request "
                    + requestContext.getInboundSAMLMessageId() + " from relying party "
                    + requestContext.getInboundMessageIssuer(), e);
        }
    }

    /**
     * Executes a query for attributes and builds a SAML attribute statement from the results.
     * 
     * @param requestContext current request context
     * 
     * @return attribute statement resulting from the query
     * 
     * @throws ProfileException thrown if there is a problem making the query
     */
    protected AttributeStatement buildAttributeStatement(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {
        log.debug("Creating attribute statement in response to SAML request {} from relying party {}", requestContext
                .getInboundSAMLMessageId(), requestContext.getInboundMessageIssuer());

        AbstractSAML2ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();
        try {
            if (requestContext.getInboundSAMLMessage() instanceof AttributeQuery) {
                return attributeAuthority.buildAttributeStatement((AttributeQuery) requestContext
                        .getInboundSAMLMessage(), requestContext.getPrincipalAttributes().values());
            } else {
                return attributeAuthority.buildAttributeStatement(null, requestContext.getPrincipalAttributes()
                        .values());
            }
        } catch (AttributeRequestException e) {
            log.error("Error encoding attributes for principal " + requestContext.getPrincipalName(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Error resolving attributes"));
            throw new ProfileException("Error encoding attributes for principal " + requestContext.getPrincipalName(),
                    e);
        }
    }

    /**
     * Resolves the principal name of the subject of the request.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the principal name can not be resolved
     */
    protected void resolvePrincipal(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML2ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        if (profileConfiguration == null) {
            log.error("Unable to resolve principal, no SAML 2 profile configuration for relying party "
                    + requestContext.getInboundMessageIssuer());
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI,
                    "Error resolving principal"));
            throw new ProfileException(
                    "Unable to resolve principal, no SAML 2 profile configuration for relying party "
                            + requestContext.getInboundMessageIssuer());
        }
        SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();
        log.debug("Resolving principal name for subject of SAML request {} from relying party {}", requestContext
                .getInboundSAMLMessageId(), requestContext.getInboundMessageIssuer());

        try {
            String principal = attributeAuthority.getPrincipal(requestContext);
            requestContext.setPrincipalName(principal);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes for SAML request " + requestContext.getInboundSAMLMessageId()
                    + " from relying party " + requestContext.getInboundMessageIssuer(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.UNKNOWN_PRINCIPAL_URI,
                    "Error resolving principal"));
            throw new ProfileException("Error resolving attributes for SAML request "
                    + requestContext.getInboundSAMLMessageId() + " from relying party "
                    + requestContext.getInboundMessageIssuer(), e);
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
    protected void signAssertion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, Assertion assertion)
            throws ProfileException {
        log.debug("Determining if SAML assertion to relying party {} should be signed", requestContext
                .getInboundMessageIssuer());

        boolean signAssertion = false;

        AbstractSAML2ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();
        if (profileConfig.getSignAssertions()) {
            signAssertion = true;
            log.debug("IdP relying party configuration {} indicates to sign assertions: {}", requestContext
                    .getRelyingPartyConfiguration().getRelyingPartyId(), signAssertion);
        }

        if (!signAssertion && requestContext.getPeerEntityRoleMetadata() instanceof SPSSODescriptor) {
            SPSSODescriptor ssoDescriptor = (SPSSODescriptor) requestContext.getPeerEntityRoleMetadata();
            if (ssoDescriptor.getWantAssertionsSigned() != null) {
                signAssertion = ssoDescriptor.getWantAssertionsSigned().booleanValue();
                log.debug("Entity metadata for relying party {} indicates to sign assertions: {}", requestContext
                        .getInboundMessageIssuer(), signAssertion);
            }
        }

        if (!signAssertion) {
            return;
        }

        log.debug("Determining signing credntial for assertion to relying party {}", requestContext
                .getInboundMessageIssuer());
        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();
        }

        if (signatureCredential == null) {
            throw new ProfileException("No signing credential is specified for relying party configuration "
                    + requestContext.getRelyingPartyConfiguration().getProviderId()
                    + " or it's SAML2 attribute query profile configuration");
        }

        log.debug("Signing assertion to relying party {}", requestContext.getInboundMessageIssuer());
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signatureCredential);
        try {
            // TODO pull SecurityConfiguration from SAMLMessageContext? needs to be added
            // TODO how to pull what keyInfoGenName to use?
            SecurityHelper.prepareSignatureParams(signature, signatureCredential, null, null);
        } catch (SecurityException e) {
            throw new ProfileException("Error preparing signature for signing", e);
        }

        assertion.setSignature(signature);

        Signer.signObject(signature);
    }

    /**
     * Build a status message, with an optional second-level failure message.
     * 
     * @param topLevelCode The top-level status code. Should be from saml-core-2.0-os, sec. 3.2.2.2
     * @param secondLevelCode An optional second-level failure code. Should be from saml-core-2.0-is, sec 3.2.2.2. If
     *            null, no second-level Status element will be set.
     * @param failureMessage An optional second-level failure message
     * 
     * @return a Status object.
     */
    protected Status buildStatus(String topLevelCode, String secondLevelCode, String failureMessage) {
        Status status = statusBuilder.buildObject();

        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(DatatypeHelper.safeTrimOrNullString(topLevelCode));
        status.setStatusCode(statusCode);

        if (secondLevelCode != null) {
            StatusCode secondLevelStatusCode = statusCodeBuilder.buildObject();
            secondLevelStatusCode.setValue(DatatypeHelper.safeTrimOrNullString(secondLevelCode));
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
     * Builds the SAML subject for the user for the service provider.
     * 
     * @param requestContext current request context
     * @param confirmationMethod subject confirmation method used for the subject
     * @param issueInstant instant the subject confirmation data should reflect for issuance
     * 
     * @return SAML subject for the user for the service provider
     * 
     * @throws ProfileException thrown if a NameID can not be created either because there was a problem encoding the
     *             name ID attribute or because there are no supported name formats
     */
    protected Subject buildSubject(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, String confirmationMethod,
            DateTime issueInstant) throws ProfileException {
        NameID nameID = buildNameId(requestContext);
        requestContext.setSubjectNameIdentifier(nameID);
        // TODO handle encryption

        SubjectConfirmationData confirmationData = subjectConfirmationDataBuilder.buildObject();
        HTTPInTransport inTransport = (HTTPInTransport) requestContext.getInboundMessageTransport();
        confirmationData.setAddress(inTransport.getPeerAddress());
        confirmationData.setInResponseTo(requestContext.getInboundSAMLMessageId());
        confirmationData.setNotOnOrAfter(issueInstant.plus(requestContext.getProfileConfiguration()
                .getAssertionLifetime()));

        Endpoint relyingPartyEndpoint = requestContext.getPeerEntityEndpoint();
        if (relyingPartyEndpoint != null) {
            if (relyingPartyEndpoint.getResponseLocation() != null) {
                confirmationData.setRecipient(relyingPartyEndpoint.getResponseLocation());
            } else {
                confirmationData.setRecipient(relyingPartyEndpoint.getLocation());
            }
        }

        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(confirmationMethod);
        subjectConfirmation.setSubjectConfirmationData(confirmationData);

        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameID);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }

    /**
     * Builds a NameID appropriate for this request. NameIDs are built by inspecting the SAML request and metadata,
     * picking a name format that was requested by the relying party or is mutually supported by both the relying party
     * and asserting party as described in their metadata entries. Once a set of supported name formats is determined
     * the principals attributes are inspected for an attribute supported an attribute encoder whose category is one of
     * the supported name formats.
     * 
     * @param requestContext current request context
     * 
     * @return the NameID appropriate for this request
     * 
     * @throws ProfileException thrown if a NameID can not be created either because there was a problem encoding the
     *             name ID attribute or because there are no supported name formats
     */
    protected NameID buildNameId(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        log.debug("Building assertion NameID for principal/relying party:{}/{}", requestContext.getPrincipalName(),
                requestContext.getInboundMessageIssuer());
        Map<String, BaseAttribute> principalAttributes = requestContext.getPrincipalAttributes();
        List<String> supportedNameFormats = getNameFormats(requestContext);

        log.debug("Supported NameID formats: {}", supportedNameFormats);

        if (principalAttributes == null || supportedNameFormats == null) {
            log.error("No attributes for principal " + requestContext.getPrincipalName()
                    + " support constructions of NameID");
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.INVALID_NAMEID_POLICY_URI,
                    "Unable to construct NameID"));
            throw new ProfileException("No principal attributes support NameID construction");
        }

        try {
            SAML2NameIDAttributeEncoder nameIdEncoder;
            for (BaseAttribute<?> attribute : principalAttributes.values()) {
                for (AttributeEncoder encoder : attribute.getEncoders()) {
                    if (encoder instanceof SAML2NameIDAttributeEncoder) {
                        nameIdEncoder = (SAML2NameIDAttributeEncoder) encoder;
                        if (supportedNameFormats.contains(nameIdEncoder.getNameFormat())) {
                            log
                                    .debug(
                                            "Using attribute {} suppoting NameID format {} to create the NameID for principal.{}",
                                            attribute.getId(), nameIdEncoder.getNameFormat());
                            return nameIdEncoder.encode(attribute);
                        }
                    }
                }
            }
            log.error("No principal attribute supported encoding into a supported name ID format.");
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Unable to construct NameID"));
            throw new ProfileException("No principal attribute supported encoding into a supported name ID format.");
        } catch (AttributeEncodingException e) {
            log.error("Unable to encode NameID attribute", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Unable to construct NameID"));
            throw new ProfileException("Unable to encode NameID attribute", e);
        }
    }

    /**
     * Gets the NameID format to use when creating NameIDs for the relying party.
     * 
     * @param requestContext current request context
     * 
     * @return list of nameID formats that may be used with the relying party
     * 
     * @throws ProfileException thrown if there is a problem determing the NameID format to use
     */
    protected List<String> getNameFormats(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {
        ArrayList<String> nameFormats = new ArrayList<String>();

        // Determine name formats supported by both SP and IdP
        RoleDescriptor relyingPartyRole = requestContext.getPeerEntityRoleMetadata();
        if (relyingPartyRole != null) {
            List<String> relyingPartySupportedFormats = getEntitySupportedFormats(relyingPartyRole);
            if (relyingPartySupportedFormats != null && !relyingPartySupportedFormats.isEmpty()) {
                nameFormats.addAll(relyingPartySupportedFormats);

                RoleDescriptor assertingPartyRole = requestContext.getLocalEntityRoleMetadata();
                if (assertingPartyRole != null) {
                    List<String> assertingPartySupportedFormats = getEntitySupportedFormats(assertingPartyRole);
                    if (assertingPartySupportedFormats != null && !assertingPartySupportedFormats.isEmpty()) {
                        nameFormats.retainAll(assertingPartySupportedFormats);
                    }
                }
            }
        }

        if (nameFormats.isEmpty()) {
            nameFormats.add("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
        }

        // If authn request and name ID policy format specified, make sure it's in the list of supported formats
        String nameFormat = null;
        if (requestContext.getInboundSAMLMessage() instanceof AuthnRequest) {
            AuthnRequest authnRequest = (AuthnRequest) requestContext.getInboundSAMLMessage();
            if (authnRequest.getNameIDPolicy() != null) {
                nameFormat = DatatypeHelper.safeTrimOrNullString(authnRequest.getNameIDPolicy().getFormat());
                if (nameFormat != null) {
                    if (nameFormats.contains(nameFormat)) {
                        nameFormats.clear();
                        nameFormats.add(nameFormat);
                    } else {
                        requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI,
                                StatusCode.INVALID_NAMEID_POLICY_URI, "Format not supported: " + nameFormat));
                        throw new ProfileException("NameID format required by relying party is not supported");
                    }
                }

            }
        }

        return nameFormats;
    }

    /**
     * Gets the list of NameID formats supported for a given role.
     * 
     * @param role the role to get the list of supported NameID formats
     * 
     * @return list of supported NameID formats
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
     * @param requestContext current request context
     * 
     * @return the constructed error response
     */
    protected Response buildErrorResponse(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) {
        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(new DateTime());
        populateStatusResponse(requestContext, samlResponse);

        samlResponse.setStatus(requestContext.getFailureStatus());

        return samlResponse;
    }
}