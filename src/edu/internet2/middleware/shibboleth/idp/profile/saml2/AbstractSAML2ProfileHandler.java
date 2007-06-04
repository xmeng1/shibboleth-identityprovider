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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.log.Level;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.ProxyRestriction;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AuthnAuthorityDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AbstractSAML2ProfileConfiguration;
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

    /** For builder subject confirmation. */
    private SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder;

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
        conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) getBuilderFactory().getBuilder(
                AudienceRestriction.DEFAULT_ELEMENT_NAME);
        proxyRestrictionBuilder = (SAMLObjectBuilder<ProxyRestriction>) getBuilderFactory().getBuilder(
                ProxyRestriction.DEFAULT_ELEMENT_NAME);
        audienceBuilder = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        adviceBuilder = (SAMLObjectBuilder<Advice>) getBuilderFactory().getBuilder(Advice.DEFAULT_ELEMENT_NAME);
        signatureBuilder = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
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
     * Convenience method for getting the SAML 2 subject confirmation builder.
     * 
     * @return SAML 2 subject confirmation builder
     */
    public SAMLObjectBuilder<SubjectConfirmation> getSubjectConfirmationBuilder() {
        return subjectConfirmationBuilder;
    }

    /**
     * Builds a response to the attribute query within the request context.
     * 
     * @param requestContext current request context
     * @param assertionSubject subject of the assertion within the response
     * @param statements the statements to include in the response
     * 
     * @return the built response
     * 
     * @throws ProfileException thrown if there is a problem creating the SAML response
     * @throws AttributeRequestException thrown if there is a problem resolving attributes
     */
    protected Response buildResponse(SAML2ProfileRequestContext requestContext, Subject assertionSubject,
            List<Statement> statements) throws ProfileException, AttributeRequestException {

        DateTime issueInstant = new DateTime();

        // create the assertion and add the attribute statement
        Assertion assertion = buildAssertion(requestContext, issueInstant);
        assertion.setSubject(assertionSubject);
        if (statements != null) {
            assertion.getStatements().addAll(statements);
        }

        // create the SAML response and add the assertion
        Response samlResponse = getResponseBuilder().buildObject();
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
    protected Assertion buildAssertion(SAML2ProfileRequestContext requestContext, DateTime issueInstant) {

        Assertion assertion = getAssertionBuilder().buildObject();
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
    protected Issuer buildEntityIssuer(SAML2ProfileRequestContext requestContext) {
        Issuer issuer = getIssuerBuilder().buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(requestContext.getRelyingPartyId());

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
    protected Conditions buildConditions(SAML2ProfileRequestContext requestContext, DateTime issueInstant) {
        AbstractSAML2ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        Conditions conditions = getConditionsBuilder().buildObject();
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(issueInstant.plus(profileConfig.getAssertionLifetime()));

        Collection<String> audiences;

        // add audience restrictions
        audiences = profileConfig.getAssertionAudiences();
        if (audiences != null && audiences.size() > 0) {
            AudienceRestriction audienceRestriction = getAudienceRestrictionBuilder().buildObject();
            for (String audienceUri : audiences) {
                Audience audience = getAudienceBuilder().buildObject();
                audience.setAudienceURI(audienceUri);
                audienceRestriction.getAudiences().add(audience);
            }
            conditions.getAudienceRestrictions().add(audienceRestriction);
        }

        // add proxy restrictions
        audiences = profileConfig.getProxyAudiences();
        if (audiences != null && audiences.size() > 0) {
            ProxyRestriction proxyRestriction = getProxyRestrictionBuilder().buildObject();
            Audience audience;
            for (String audienceUri : audiences) {
                audience = getAudienceBuilder().buildObject();
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
    protected void populateStatusResponse(SAML2ProfileRequestContext requestContext, StatusResponseType response) {
        response.setID(getIdGenerator().generateIdentifier());
        response.setInResponseTo(requestContext.getSamlRequest().getID());
        response.setIssueInstant(response.getIssueInstant());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssuer(buildEntityIssuer(requestContext));
    }

    /**
     * Signs the given assertion if either the current profile configuration or the relying party configuration contains
     * signing credentials.
     * 
     * @param requestContext current request context
     * @param assertion assertion to sign
     */
    protected void signAssertion(SAML2ProfileRequestContext requestContext, Assertion assertion) {
        AbstractSAML2ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        if (!profileConfig.getSignAssertions()) {
            return;
        }

        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();
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
     * Build a status message, with an optional second-level failure message.
     * 
     * @param topLevelCode The top-level status code. Should be from saml-core-2.0-os, sec. 3.2.2.2
     * @param secondLevelCode An optional second-level failure code. Should be from saml-core-2.0-is, sec 3.2.2.2. If
     *            null, no second-level Status element will be set.
     * @param secondLevelFailureMessage An optional second-level failure message
     * 
     * @return a Status object.
     */
    protected Status buildStatus(String topLevelCode, String secondLevelCode, String secondLevelFailureMessage) {

        Status status = getStatusBuilder().buildObject();

        StatusCode statusCode = getStatusCodeBuilder().buildObject();
        statusCode.setValue(DatatypeHelper.safeTrimOrNullString(topLevelCode));
        status.setStatusCode(statusCode);

        if (secondLevelCode != null) {
            StatusCode secondLevelStatusCode = getStatusCodeBuilder().buildObject();
            secondLevelStatusCode.setValue(DatatypeHelper.safeTrimOrNullString(secondLevelCode));
            statusCode.setStatusCode(secondLevelStatusCode);
        }

        if (secondLevelFailureMessage != null) {
            StatusMessage msg = getStatusMessageBuilder().buildObject();
            msg.setMessage(secondLevelFailureMessage);
            status.setStatusMessage(msg);
        }

        return status;
    }

    /**
     * Builds the SAML subject for the user for the service provider.
     * 
     * @param requestContext current request context
     * @param confirmationMethod subject confirmation method used for the subject
     * 
     * @return SAML subject for the user for the service provider
     */
    protected Subject buildSubject(SAML2ProfileRequestContext requestContext, String confirmationMethod) {
        NameID nameID = requestContext.getSubjectNameID();
        // TODO handle encryption

        SubjectConfirmation subjectConfirmation = getSubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod(confirmationMethod);

        Subject subject = getSubjectBuilder().buildObject();
        subject.setNameID(nameID);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }

    /**
     * Constructs an SAML response message carrying a request error.
     * 
     * @param requestContext current request context
     * @param topLevelCode The top-level status code. Should be from saml-core-2.0-os, sec. 3.2.2.2
     * @param secondLevelCode An optional second-level failure code. Should be from saml-core-2.0-is, sec 3.2.2.2. If
     *            null, no second-level Status element will be set.
     * @param secondLevelFailureMessage An optional second-level failure message
     * 
     * @return the constructed error response
     */
    protected Response buildErrorResponse(SAML2ProfileRequestContext requestContext, String topLevelCode,
            String secondLevelCode, String secondLevelFailureMessage) {
        Response samlResponse = getResponseBuilder().buildObject();
        samlResponse.setIssueInstant(new DateTime());
        populateStatusResponse(requestContext, samlResponse);

        Status status = buildStatus(topLevelCode, secondLevelCode, secondLevelFailureMessage);
        samlResponse.setStatus(status);

        return samlResponse;
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
    protected List<String> getNameIDFormat(SAML2ProfileRequestContext requestContext) throws ProfileException {
        ArrayList<String> nameFormats = new ArrayList<String>();

        try {
            RoleDescriptor assertingPartyRole = getMetadataProvider().getRole(requestContext.getAssertingPartyId(),
                    requestContext.getAssertingPartyRole(), SAMLConstants.SAML20P_NS);
            List<String> assertingPartySupportedFormats = getEntitySupportedFormats(assertingPartyRole);

            String nameFormat = null;
            if (requestContext.getSamlRequest() instanceof AuthnRequest) {
                AuthnRequest authnRequest = (AuthnRequest) requestContext.getSamlRequest();
                if (authnRequest.getNameIDPolicy() != null) {
                    nameFormat = authnRequest.getNameIDPolicy().getFormat();
                    if (assertingPartySupportedFormats.contains(nameFormat)) {
                        nameFormats.add(nameFormat);
                    } else {
                        throw new ProfileException("NameID format required by relying party is not supported");
                    }
                }
            }

            if (nameFormats.isEmpty()) {
                RoleDescriptor relyingPartyRole = getMetadataProvider().getRole(requestContext.getRelyingPartyId(),
                        requestContext.getRelyingPartyRole(), SAMLConstants.SAML20P_NS);
                List<String> relyingPartySupportedFormats = getEntitySupportedFormats(relyingPartyRole);

                assertingPartySupportedFormats.retainAll(relyingPartySupportedFormats);
                nameFormats.addAll(assertingPartySupportedFormats);
            }
            if (nameFormats.isEmpty()) {
                nameFormats.add("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
            }

            return nameFormats;

        } catch (MetadataProviderException e) {
            throw new ProfileException("Unable to determine lookup entity metadata", e);
        }
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
     * Writes an aduit log entry indicating the successful response to the attribute request.
     * 
     * @param context current request context
     */
    protected void writeAuditLogEntry(SAML2ProfileRequestContext context) {
        AuditLogEntry auditLogEntry = new AuditLogEntry();
        auditLogEntry.setMessageProfile(getProfileId());
        auditLogEntry.setPrincipalAuthenticationMethod(context.getPrincipalAuthenticationMethod());
        auditLogEntry.setPrincipalName(context.getPrincipalName());
        auditLogEntry.setAssertingPartyId(context.getAssertingPartyId());
        auditLogEntry.setRelyingPartyId(context.getRelyingPartyId());
        auditLogEntry.setRequestBinding(context.getMessageDecoder().getBindingURI());
        auditLogEntry.setRequestId(context.getSamlRequest().getID());
        auditLogEntry.setResponseBinding(context.getMessageEncoder().getBindingURI());
        auditLogEntry.setResponseId(context.getSamlResponse().getID());
        getAduitLog().log(Level.CRITICAL, auditLogEntry);
    }

    /**
     * Contextual object used to accumlate information as profile requests are being processed.
     * 
     * @param <RequestType> type of SAML 2 request
     * @param <ResponseType> type of SAML 2 response
     * @param <ProfileConfigurationType> configuration type for this profile
     */
    protected class SAML2ProfileRequestContext<RequestType extends RequestAbstractType, 
                                               ResponseType extends StatusResponseType, 
                                               ProfileConfigurationType extends AbstractSAML2ProfileConfiguration>
            extends SAMLProfileRequestContext {

        /** SAML request message. */
        private RequestType samlRequest;

        /** SAML response message. */
        private ResponseType samlResponse;

        /** Request profile configuration. */
        private ProfileConfigurationType profileConfiguration;

        /** The NameID of the subject of this request. */
        private NameID subjectNameID;

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public SAML2ProfileRequestContext(ProfileRequest<ServletRequest> request,
                ProfileResponse<ServletResponse> response) {
            super(request, response);
        }

        /**
         * Gets the NameID of the subject of this request.
         * 
         * @return NameID of the subject of this request
         */
        public NameID getSubjectNameID() {
            return subjectNameID;
        }

        /**
         * Sets the NameID of the subject of this request.
         * 
         * @param nameID NameID of the subject of this request
         */
        public void setSubjectNameID(NameID nameID) {
            subjectNameID = nameID;
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
    }
}