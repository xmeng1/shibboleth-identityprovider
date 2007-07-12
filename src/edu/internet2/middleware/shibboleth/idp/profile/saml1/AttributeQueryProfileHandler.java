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

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import java.util.ArrayList;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.common.binding.encoding.MessageEncoder;
import org.opensaml.common.binding.security.SAMLSecurityPolicy;
import org.opensaml.saml1.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml1.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.security.SecurityPolicyException;

import edu.internet2.middleware.shibboleth.common.ShibbolethConstants;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AttributeQueryConfiguration;

/**
 * SAML 1 Attribute Query profile handler.
 */
public class AttributeQueryProfileHandler extends AbstractSAML1ProfileHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(AttributeQueryProfileHandler.class);

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml1:query:attribute";
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response)
            throws ProfileException {

        AttributeQueryContext requestContext = new AttributeQueryContext(request, response);

        Response samlResponse;
        try {
            decodeRequest(requestContext);

            if (requestContext.getRelyingPartyConfiguration() == null) {
                log.error("SAML 1 Attribute Query profile is not configured for relying party "
                        + requestContext.getRelyingPartyId());
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                        "SAML 1 Attribute Query profile is not configured for relying party "
                                + requestContext.getRelyingPartyId()));
                samlResponse = buildErrorResponse(requestContext);
            }

            resolvePrincipal(requestContext);
            resolveAttributes(requestContext);

            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAttributeStatement(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"));

            samlResponse = buildResponse(requestContext, statements);
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext);
        }

        requestContext.setSamlResponse(samlResponse);
        encodeResponse(requestContext);
    }

    /**
     * Decodes the message in the request and adds it to the request context.
     * 
     * @param requestContext request context contianing the request to decode
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected void decodeRequest(AttributeQueryContext requestContext) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Decoding incomming request");
        }
        MessageDecoder<ServletRequest> decoder = getMessageDecoderFactory().getMessageDecoder(
                HTTPSOAP11Decoder.BINDING_URI);
        if (decoder == null) {
            throw new ProfileException("No request decoder was registered for binding type: "
                    + HTTPSOAP11Decoder.BINDING_URI);
        }
        super.populateMessageDecoder(decoder);

        ProfileRequest<ServletRequest> profileRequest = requestContext.getProfileRequest();
        decoder.setRequest(profileRequest.getRawRequest());
        requestContext.setMessageDecoder(decoder.getBindingURI());

        try {
            decoder.decode();
            if (log.isDebugEnabled()) {
                log.debug("Decoded request");
            }
        } catch (BindingException e) {
            log.error("Error decoding attribute query message", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error decoding message"));
            throw new ProfileException("Error decoding attribute query message");
        } catch (SecurityPolicyException e) {
            log.error("Message did not meet security policy requirements", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Message did not meet security policy requirements"));
            throw new ProfileException("Message did not meet security policy requirements", e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            SAMLSecurityPolicy securityPolicy = decoder.getSecurityPolicy();
            requestContext.setRelyingPartyId(securityPolicy.getIssuer());

            Request request = (Request) decoder.getSAMLMessage();
            requestContext.setSamlRequest(request);
            requestContext.setAttributeQuery(request.getAttributeQuery());

            populateRelyingPartyData(requestContext);

            populateAssertingPartyData(requestContext);
        }
    }

    /**
     * Populates the relying party entity and role metadata and relying party configuration data.
     * 
     * @param requestContext current request context with relying party ID populated
     * 
     * @throws ProfileException thrown if metadata can not be located for the relying party
     */
    protected void populateRelyingPartyData(AttributeQueryContext requestContext) throws ProfileException {
        try {
            requestContext.setRelyingPartyMetadata(getMetadataProvider().getEntityDescriptor(
                    requestContext.getRelyingPartyId()));

            RoleDescriptor relyingPartyRole = requestContext.getRelyingPartyMetadata().getSPSSODescriptor(
                    ShibbolethConstants.SAML11P_NS);

            if (relyingPartyRole == null) {
                relyingPartyRole = requestContext.getRelyingPartyMetadata().getSPSSODescriptor(
                        ShibbolethConstants.SAML10P_NS);
                if (relyingPartyRole == null) {
                    throw new MetadataProviderException("Unable to locate SPSSO role descriptor for entity "
                            + requestContext.getRelyingPartyId());
                }
            }
            requestContext.setRelyingPartyRoleMetadata(relyingPartyRole);

            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(requestContext.getRelyingPartyId());
            requestContext.setRelyingPartyConfiguration(rpConfig);

            requestContext.setProfileConfiguration((AttributeQueryConfiguration) rpConfig
                    .getProfileConfiguration(AttributeQueryConfiguration.PROFILE_ID));

        } catch (MetadataProviderException e) {
            log.error("Unable to locate metadata for relying party " + requestContext.getRelyingPartyId());
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                    "Unable to locate metadata for relying party " + requestContext.getRelyingPartyId()));
            throw new ProfileException("Unable to locate metadata for relying party "
                    + requestContext.getRelyingPartyId());
        }
    }

    /**
     * Populates the asserting party entity and role metadata.
     * 
     * @param requestContext current request context with relying party configuration populated
     * 
     * @throws ProfileException thrown if metadata can not be located for the asserting party
     */
    protected void populateAssertingPartyData(AttributeQueryContext requestContext) throws ProfileException {
        String assertingPartyId = requestContext.getRelyingPartyConfiguration().getProviderId();

        try {
            requestContext.setAssertingPartyId(assertingPartyId);

            requestContext.setAssertingPartyMetadata(getMetadataProvider().getEntityDescriptor(assertingPartyId));

            RoleDescriptor assertingPartyRole = requestContext.getAssertingPartyMetadata()
                    .getAttributeAuthorityDescriptor(ShibbolethConstants.SAML11P_NS);

            if (assertingPartyRole == null) {
                assertingPartyRole = requestContext.getAssertingPartyMetadata().getAttributeAuthorityDescriptor(
                        ShibbolethConstants.SAML10P_NS);
                if (assertingPartyRole == null) {
                    throw new MetadataProviderException("Unable to locate IDPSSO role descriptor for entity "
                            + assertingPartyId);
                }
            }
            requestContext.setAssertingPartyRoleMetadata(assertingPartyRole);
        } catch (MetadataProviderException e) {
            log.error("Unable to locate metadata for asserting party " + assertingPartyId);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                    "Unable to locate metadata for relying party " + assertingPartyId));
            throw new ProfileException("Unable to locate metadata for relying party " + assertingPartyId);
        }
    }

    /**
     * Encodes the request's SAML response and writes it to the servlet response.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if no message encoder is registered for this profiles binding
     */
    protected void encodeResponse(AttributeQueryContext requestContext) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Encoding response to SAML request from relying party " + requestContext.getRelyingPartyId());
        }
        MessageEncoder<ServletResponse> encoder = getMessageEncoderFactory().getMessageEncoder(
                HTTPSOAP11Encoder.BINDING_URI);
        if (encoder == null) {
            throw new ProfileException("No response encoder was registered for binding type: "
                    + HTTPSOAP11Encoder.BINDING_URI);
        }

        super.populateMessageEncoder(encoder);
        encoder.setRelayState(requestContext.getRelayState());
        ProfileResponse<ServletResponse> profileResponse = requestContext.getProfileResponse();
        encoder.setResponse(profileResponse.getRawResponse());
        encoder.setSamlMessage(requestContext.getSamlResponse());
        requestContext.setMessageEncoder(encoder.getBindingURI());

        try {
            encoder.encode();
        } catch (BindingException e) {
            throw new ProfileException("Unable to encode response to relying party: "
                    + requestContext.getRelyingPartyId(), e);
        }
    }

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryContext extends
            SAML1ProfileRequestContext<Request, Response, AttributeQueryConfiguration> {

        /** Current attribute query. */
        private AttributeQuery attributeQuery;

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public AttributeQueryContext(ProfileRequest<ServletRequest> request, 
                ProfileResponse<ServletResponse> response) {
            super(request, response);
        }

        /**
         * Gets the attribute query of the request.
         * 
         * @return attribute query of the request
         */
        public AttributeQuery getAttributeQuery() {
            return attributeQuery;
        }

        /**
         * Sets the attribute query of the request.
         * 
         * @param query attribute query of the request
         */
        public void setAttributeQuery(AttributeQuery query) {
            attributeQuery = query;
        }
    }
}