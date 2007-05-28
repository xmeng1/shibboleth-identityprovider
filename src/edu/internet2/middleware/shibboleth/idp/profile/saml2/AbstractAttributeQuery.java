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
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

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

        AttributeQueryRequestContext requestContext = new AttributeQueryRequestContext(request, response);

        getMessageDecoder(requestContext);
        
        decodeRequest(requestContext);

        buildResponse(requestContext);

        getMessageEncoder(requestContext);

        try {
            requestContext.getMessageEncoder().encode();
            writeAuditLogEntry(requestContext);
        } catch (BindingException e) {
            log.error("Unable to encode response the relying party: " + requestContext.getRelyingPartyId(), e);
            throw new ProfileException("Unable to encode response the relying party: "
                    + requestContext.getRelyingPartyId(), e);
        }
    }

    /**
     * Gets a populated message decoder.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is no message decoder that may be used to decoder the incoming request
     */
    protected abstract void getMessageDecoder(AttributeQueryRequestContext requestContext) throws ProfileException;

    /**
     * Gets a populated message encoder.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is no message encoder that may be used to encoder the outgoing response
     */
    protected abstract void getMessageEncoder(AttributeQueryRequestContext requestContext) throws ProfileException;

    /**
     * Decodes the message in the request and adds it to the request context.
     * 
     * @param requestContext request context contianing the request to decode
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected void decodeRequest(AttributeQueryRequestContext requestContext)
            throws ProfileException {

        try {
            requestContext.getMessageDecoder().decode();
            if (log.isDebugEnabled()) {
                log.debug("decoded http servlet request");
            }
            requestContext.setAttributeQuery((AttributeQuery) requestContext.getMessageDecoder().getSAMLMessage());
        } catch (BindingException e) {
            log.error("Error decoding attribute query message", e);
            throw new ProfileException("Error decoding attribute query message");
        }
    }

    /**
     * Builds a response to the attribute query within the request context.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is a problem creating the SAML response
     */
    protected void buildResponse(AttributeQueryRequestContext requestContext) throws ProfileException {
        DateTime issueInstant = new DateTime();

        // create the attribute statement
        AttributeStatement attributeStatement = buildAttributeStatement(requestContext);

        // create the assertion and add the attribute statement
        Assertion assertion = buildAssertion(issueInstant, requestContext.getRelyingPartyConfiguration(),
                requestContext.getProfileConfiguration());
        assertion.getAttributeStatements().add(attributeStatement);

        // create the SAML response and add the assertion
        Response samlResponse = getResponseBuilder().buildObject();
        populateStatusResponse(samlResponse, issueInstant, requestContext.getAttributeQuery(), requestContext
                .getRelyingPartyConfiguration());
        
        // TODO handle subject
        samlResponse.getAssertions().add(assertion);

        // sign the assertion if it should be signed
        signAssertion(assertion, requestContext.getRelyingPartyConfiguration(), requestContext
                .getProfileConfiguration());

        requestContext.setAttributeQueryResponse(samlResponse);
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
    protected AttributeStatement buildAttributeStatement(AttributeQueryRequestContext requestContext)
            throws ProfileException {
        ShibbolethAttributeRequestContext attributeRequestContext = buildAttributeRequestContext(requestContext
                .getRelyingPartyId(), requestContext.getUserSession(), requestContext.getProfileRequest());

        try {
            SAML2AttributeAuthority attributeAuthority = requestContext.getProfileConfiguration()
                    .getAttributeAuthority();
            return attributeAuthority.performAttributeQuery(attributeRequestContext);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes", e);
            throw new ProfileException("Error resolving attributes", e);
        }
    }

    /**
     * Builds an attribute request context for this request.
     * 
     * @param spEntityId entity ID of the service provider
     * @param userSession current user's session
     * @param request current request
     * 
     * @return the attribute request context
     * 
     * @throws ProfileException thrown if the metadata information can not be located for the given service provider
     */
    protected ShibbolethAttributeRequestContext buildAttributeRequestContext(String spEntityId, Session userSession,
            ProfileRequest<ServletRequest> request) throws ProfileException {
        ServiceInformation spInformation = userSession.getServiceInformation(spEntityId);
        ShibbolethAttributeRequestContext requestContext = null;
        try {
            requestContext = new ShibbolethAttributeRequestContext(getMetadataProvider(),
                    getRelyingPartyConfiguration(spEntityId));
            requestContext.setPrincipalName(userSession.getPrincipalID());
            requestContext.setPrincipalAuthenticationMethod(spInformation.getAuthenticationMethod()
                    .getAuthenticationMethod());
            requestContext.setRequest(request.getRawRequest());
            return requestContext;
        } catch (MetadataProviderException e) {
            log.error("Error creating ShibbolethAttributeRequestContext", e);
            throw new ProfileException("Error retrieving metadata", e);
        }
    }

    /**
     * Writes an aduit log entry indicating the successful response to the attribute request.
     * 
     * @param requestContext current request context
     */
    protected void writeAuditLogEntry(AttributeQueryRequestContext requestContext) {
        AuditLogEntry auditLogEntry = new AuditLogEntry();
        auditLogEntry.setMessageProfile(getProfileId());
        auditLogEntry.setPrincipalAuthenticationMethod(requestContext.getUserSession().getServiceInformation(
                requestContext.getRelyingPartyId()).getAuthenticationMethod().getAuthenticationMethod());
        auditLogEntry.setPrincipalId(requestContext.getUserSession().getPrincipalID());
        auditLogEntry.setProviderId(requestContext.getRelyingPartyConfiguration().getProviderId());
        auditLogEntry.setRelyingPartyId(requestContext.getRelyingPartyId());
        auditLogEntry.setRequestBinding(requestContext.getMessageDecoder().getBindingURI());
        auditLogEntry.setRequestId(requestContext.getAttributeQuery().getID());
        auditLogEntry.setResponseBinding(requestContext.getMessageEncoder().getBindingURI());
        auditLogEntry.setResponseId(requestContext.getAttributeQueryResponse().getID());
        getAduitLog().log(Level.CRITICAL, auditLogEntry);
    }

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryRequestContext {

        /** Current user's session. */
        private Session userSession;

        /** Current profile request. */
        private ProfileRequest<ServletRequest> profileRequest;

        /** Decoder used to decode the incoming request. */
        private MessageDecoder<ServletRequest> messageDecoder;

        /** Current profile response. */
        private ProfileResponse<ServletResponse> profileResponse;

        /** Encoder used to encode the outgoing response. */
        private MessageEncoder<ServletResponse> messageEncoder;

        /** Attribute query made by the relying party. */
        private AttributeQuery attributeQuery;

        /** Attribute query response to the relying party. */
        private Response attributeQueryResponse;

        /** ID of the relying party. */
        private String relyingPartyId;

        /** Relying party configuration information. */
        private RelyingPartyConfiguration relyingPartyConfiguration;

        /** Attribute query profile configuration for the relying party. */
        private AttributeQueryConfiguration profileConfiguration;

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public AttributeQueryRequestContext(ProfileRequest<ServletRequest> request,
                ProfileResponse<ServletResponse> response) {
            userSession = getSessionManager().getSession(getUserSessionId(request));
            profileRequest = request;
            profileResponse = response;

        }

        /**
         * Gets the attribute query from the relying party.
         * 
         * @return attribute query from the relying party
         */
        public AttributeQuery getAttributeQuery() {
            return attributeQuery;
        }

        /**
         * Sets the attribute query from the relying party. This also populates the relying party ID, configuration, and
         * profile configuration using information from the query.
         * 
         * @param query attribute query from the relying party
         */
        public void setAttributeQuery(AttributeQuery query) {
            attributeQuery = query;
            relyingPartyId = attributeQuery.getIssuer().getValue();
            relyingPartyConfiguration = getRelyingPartyConfigurationManager().getRelyingPartyConfiguration(
                    relyingPartyId);
            profileConfiguration = (AttributeQueryConfiguration) relyingPartyConfiguration
                    .getProfileConfiguration(AttributeQueryConfiguration.PROFILE_ID);
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
         * Gets the attribute profile configuration for the relying party.
         * 
         * @return attribute profile configuration for the relying party
         */
        public AttributeQueryConfiguration getProfileConfiguration() {
            return profileConfiguration;
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

        /**
         * Gets the configuration information specific to the relying party that made the attribute query.
         * 
         * @return configuration information specific to the relying party that made the attribute query
         */
        public RelyingPartyConfiguration getRelyingPartyConfiguration() {
            return relyingPartyConfiguration;
        }

        /**
         * Gets the ID of the relying party.
         * 
         * @return ID of the relying party
         */
        public String getRelyingPartyId() {
            return relyingPartyId;
        }

        /**
         * Gets the current user's session.
         * 
         * @return current user's session
         */
        public Session getUserSession() {
            return userSession;
        }
    }
}