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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.common.binding.encoding.MessageEncoder;
import org.opensaml.log.Level;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.security.SecurityPolicyException;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethAttributeRequestContext;
import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AttributeQueryConfiguration;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * SAML 2.0 Attribute Query profile handler.
 */
public abstract class AbstractAttributeQuery extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AbstractAttributeQuery.class);

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:oasis:names:tc:SAML:2.0:profiles:query";
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response)
            throws ProfileException {

        AttributeQueryContext queryContext = new AttributeQueryContext(request, response);

        getMessageDecoder(queryContext);

        try {
            decodeRequest(queryContext);
            buildAttributeRequestContext(queryContext);
            buildResponse(queryContext);
        } catch (SecurityPolicyException e) {
            buildErrorResponse(queryContext, e);
        } catch (AttributeRequestException e) {
            buildErrorResponse(queryContext, e);
        }

        getMessageEncoder(queryContext);

        try {
            queryContext.getMessageEncoder().encode();
            writeAuditLogEntry(queryContext);
        } catch (BindingException e) {
            log.error("Unable to encode response the relying party: "
                    + queryContext.getAttributeRequestContext().getAttributeRequester(), e);
            throw new ProfileException("Unable to encode response the relying party: "
                    + queryContext.getAttributeRequestContext().getAttributeRequester(), e);
        }
    }

    /**
     * Gets a populated message decoder.
     * 
     * @param queryContext current request context
     * 
     * @throws ProfileException thrown if there is no message decoder that may be used to decoder the incoming request
     */
    protected abstract void getMessageDecoder(AttributeQueryContext queryContext) throws ProfileException;

    /**
     * Gets a populated message encoder.
     * 
     * @param queryContext current request context
     * 
     * @throws ProfileException thrown if there is no message encoder that may be used to encoder the outgoing response
     */
    protected abstract void getMessageEncoder(AttributeQueryContext queryContext) throws ProfileException;

    /**
     * Decodes the message in the request and adds it to the request context.
     * 
     * @param queryContext request context contianing the request to decode
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     * @throws SecurityPolicyException thrown if the message was decoded properly but did not meet the necessary
     *             security policy requirements
     */
    protected void decodeRequest(AttributeQueryContext queryContext) throws ProfileException, SecurityPolicyException {

        try {
            queryContext.getMessageDecoder().decode();
            if (log.isDebugEnabled()) {
                log.debug("decoded http servlet request");
            }
        } catch (BindingException e) {
            log.error("Error decoding attribute query message", e);
            throw new ProfileException("Error decoding attribute query message");
        }
    }

    /**
     * Creates an attribute request context for this attribute query and places it in the query context.
     * 
     * @param queryContext current query context
     */
    protected void buildAttributeRequestContext(AttributeQueryContext queryContext) {
        AttributeQuery attributeQuery = (AttributeQuery) queryContext.getMessageDecoder().getSAMLMessage();
        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(attributeQuery.getIssuer().getValue());

        ShibbolethAttributeRequestContext requestContext = new ShibbolethAttributeRequestContext(getMetadataProvider(),
                rpConfig, attributeQuery);
        Session userSession = getSessionManager().getSession(getUserSessionId(queryContext.getProfileRequest()));
        if (userSession != null) {
            requestContext.setUserSession(userSession);
            ServiceInformation serviceInfo = userSession.getServiceInformation(attributeQuery.getIssuer().getValue());
            if (serviceInfo != null) {
                requestContext.setPrincipalAuthenticationMethod(serviceInfo.getAuthenticationMethod()
                        .getAuthenticationMethod());
            }
        }

        requestContext.setEffectiveProfileConfiguration((AttributeQueryConfiguration) rpConfig
                .getProfileConfiguration(AttributeQueryConfiguration.PROFILE_ID));

        requestContext.setRequest(queryContext.getProfileRequest().getRawRequest());
        queryContext.setAttributeRequestContext(requestContext);
    }

    /**
     * Builds a response to the attribute query within the request context.
     * 
     * @param queryContext current request context
     * 
     * @throws ProfileException thrown if there is a problem creating the SAML response
     * @throws AttributeRequestException thrown if there is a problem resolving attributes
     */
    protected void buildResponse(AttributeQueryContext queryContext) throws ProfileException, AttributeRequestException {
        AttributeQueryConfiguration profileConfiguration = (AttributeQueryConfiguration) queryContext
                .getAttributeRequestContext().getEffectiveProfileConfiguration();
        DateTime issueInstant = new DateTime();

        // create the attribute statement
        AttributeStatement attributeStatement = buildAttributeStatement(queryContext);

        // create the assertion and add the attribute statement
        Assertion assertion = buildAssertion(issueInstant, queryContext.getAttributeRequestContext()
                .getRelyingPartyConfiguration(), profileConfiguration);
        assertion.getAttributeStatements().add(attributeStatement);

        // create the SAML response and add the assertion
        Response samlResponse = getResponseBuilder().buildObject();
        populateStatusResponse(samlResponse, issueInstant, (RequestAbstractType) queryContext
                .getAttributeRequestContext().getAttributeQuery(), queryContext.getAttributeRequestContext()
                .getRelyingPartyConfiguration());

        // TODO handle subject
        samlResponse.getAssertions().add(assertion);

        // sign the assertion if it should be signed
        signAssertion(assertion, queryContext.getAttributeRequestContext().getRelyingPartyConfiguration(),
                profileConfiguration);

        Status status = buildStatus(StatusCode.SUCCESS_URI, null, null);
        samlResponse.setStatus(status);

        queryContext.setAttributeQueryResponse(samlResponse);
    }

    /**
     * Executes a query for attributes and builds a SAML attribute statement from the results.
     * 
     * @param queryContext current request context
     * 
     * @return attribute statement resulting from the query
     * 
     * @throws ProfileException thrown if there is a problem making the query
     * @throws AttributeRequestException thrown if there is a problem resolving attributes
     */
    protected AttributeStatement buildAttributeStatement(AttributeQueryContext queryContext) throws ProfileException,
            AttributeRequestException {

        try {
            AttributeQueryConfiguration profileConfiguration = (AttributeQueryConfiguration) queryContext
                    .getAttributeRequestContext().getEffectiveProfileConfiguration();
            if (profileConfiguration == null) {
                log.error("No SAML 2 attribute query profile configuration is defined for relying party: "
                        + queryContext.getAttributeRequestContext().getRelyingPartyConfiguration().getRelyingPartyId());
                throw new AttributeRequestException(
                        "SAML 2 attribute query is not configured for this relying party");
            }

            SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();
            return attributeAuthority.performAttributeQuery(queryContext.getAttributeRequestContext());
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes", e);
            throw e;
        }
    }

    /**
     * Constructs an SAML response message carrying a request error.
     * 
     * @param queryContext current request context
     * @param error the encountered error
     */
    protected void buildErrorResponse(AttributeQueryContext queryContext, Exception error) {
        AttributeQuery attributeQuery = (AttributeQuery) queryContext.getAttributeRequestContext().getAttributeQuery();
        RelyingPartyConfiguration rpConfig = queryContext.getAttributeRequestContext().getRelyingPartyConfiguration();

        DateTime issueInstant = new DateTime();
        Response samlResponse = getResponseBuilder().buildObject();
        populateStatusResponse(samlResponse, issueInstant, attributeQuery, rpConfig);

        Status status = buildStatus(StatusCode.REQUESTER_URI, StatusCode.REQUEST_DENIED_URI, error
                .getLocalizedMessage());

        samlResponse.setStatus(status);

        queryContext.setAttributeQueryResponse(samlResponse);
    }

    /**
     * Writes an aduit log entry indicating the successful response to the attribute request.
     * 
     * @param queryContext current request context
     */
    protected void writeAuditLogEntry(AttributeQueryContext queryContext) {
        AuditLogEntry auditLogEntry = new AuditLogEntry();
        auditLogEntry.setMessageProfile(getProfileId());
        auditLogEntry.setPrincipalAuthenticationMethod(queryContext.getAttributeRequestContext()
                .getPrincipalAuthenticationMethod());
        auditLogEntry.setPrincipalId(queryContext.getAttributeRequestContext().getPrincipalName());
        auditLogEntry.setProviderId(queryContext.getAttributeRequestContext().getRelyingPartyConfiguration()
                .getProviderId());
        auditLogEntry.setRelyingPartyId(queryContext.getAttributeRequestContext().getAttributeRequester());
        auditLogEntry.setRequestBinding(queryContext.getMessageDecoder().getBindingURI());
        auditLogEntry.setRequestId(((AttributeQuery) queryContext.getAttributeRequestContext().getAttributeQuery())
                .getID());
        auditLogEntry.setResponseBinding(queryContext.getMessageEncoder().getBindingURI());
        auditLogEntry.setResponseId(queryContext.getAttributeQueryResponse().getID());
        getAduitLog().log(Level.CRITICAL, auditLogEntry);
    }

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryContext {

        /** Curent profile request. */
        private ProfileRequest<ServletRequest> profileRequest;

        /** Current profile response. */
        private ProfileResponse<ServletResponse> profileResponse;

        /** Decoder used to decode the incoming request. */
        private MessageDecoder<ServletRequest> messageDecoder;

        /** Attribute request context for this attribute query. */
        private ShibbolethAttributeRequestContext attributeRequestContext;

        /** Encoder used to encode the outgoing response. */
        private MessageEncoder<ServletResponse> messageEncoder;

        /** Attribute query response to the relying party. */
        private Response attributeQueryResponse;

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public AttributeQueryContext(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response) {
            profileRequest = request;
            profileResponse = response;
        }

        /**
         * Gets the attribute request context for this query.
         * 
         * @return attribute request context for this query
         */
        public ShibbolethAttributeRequestContext getAttributeRequestContext() {
            return attributeRequestContext;
        }

        /**
         * Sets the attribute request context for this query.
         * 
         * @param context attribute request context for this query
         */
        public void setAttributeRequestContext(ShibbolethAttributeRequestContext context) {
            attributeRequestContext = context;
        }

        /**
         * Gets the attribute query response.
         * 
         * @return attribute query response
         */
        public Response getAttributeQueryResponse() {
            return attributeQueryResponse;
        }

        /**
         * Sets the attribute query response.
         * 
         * @param response attribute query response
         */
        public void setAttributeQueryResponse(Response response) {
            attributeQueryResponse = response;
        }

        /**
         * Gets the decoder used to decode the request.
         * 
         * @return decoder used to decode the request
         */
        public MessageDecoder<ServletRequest> getMessageDecoder() {
            return messageDecoder;
        }

        /**
         * Sets the decoder used to decode the request.
         * 
         * @param decoder decoder used to decode the request
         */
        public void setMessageDecoder(MessageDecoder<ServletRequest> decoder) {
            messageDecoder = decoder;
        }

        /**
         * Gets the encoder used to encoder the response.
         * 
         * @return encoder used to encoder the response
         */
        public MessageEncoder<ServletResponse> getMessageEncoder() {
            return messageEncoder;
        }

        /**
         * Sets the encoder used to encoder the response.
         * 
         * @param encoder encoder used to encoder the response
         */
        public void setMessageEncoder(MessageEncoder<ServletResponse> encoder) {
            messageEncoder = encoder;
        }

        /**
         * Gets the current profile request.
         * 
         * @return current profile request
         */
        public ProfileRequest<ServletRequest> getProfileRequest() {
            return profileRequest;
        }

        /**
         * Gets the current profile response.
         * 
         * @return current profile response
         */
        public ProfileResponse<ServletResponse> getProfileResponse() {
            return profileResponse;
        }
    }
}