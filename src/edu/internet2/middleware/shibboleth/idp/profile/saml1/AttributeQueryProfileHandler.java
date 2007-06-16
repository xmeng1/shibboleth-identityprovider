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
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.security.SecurityPolicyException;

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

            resolvePrincipal(requestContext);

            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAttributeStatement(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"));

            samlResponse = buildResponse(requestContext, statements);
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext);
        }
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

        decoder.setRequest(requestContext.getProfileRequest().getRawRequest());
        requestContext.setMessageDecoder(decoder);

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
            SAMLSecurityPolicy securityPolicy = requestContext.getMessageDecoder().getSecurityPolicy();
            requestContext.setRelyingPartyId(securityPolicy.getIssuer());

            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(requestContext.getRelyingPartyId());
            requestContext.setRelyingPartyConfiguration(rpConfig);

            requestContext.setRelyingPartyRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

            requestContext.setAssertingPartyId(requestContext.getRelyingPartyConfiguration().getProviderId());

            requestContext.setAssertingPartyRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);

            requestContext.setProfileConfiguration((AttributeQueryConfiguration) rpConfig
                    .getProfileConfiguration(AttributeQueryConfiguration.PROFILE_ID));

            requestContext.setSamlRequest((AttributeQuery) requestContext.getMessageDecoder().getSAMLMessage());
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
        encoder.setResponse(requestContext.getProfileResponse().getRawResponse());
        encoder.setSamlMessage(requestContext.getSamlResponse());
        requestContext.setMessageEncoder(encoder);

        try {
            encoder.encode();
        } catch (BindingException e) {
            throw new ProfileException("Unable to encode response to relying party: "
                    + requestContext.getRelyingPartyId(), e);
        }
    }

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryContext extends
            SAML1ProfileRequestContext<AttributeQuery, Response, AttributeQueryConfiguration> {

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public AttributeQueryContext(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response) {
            super(request, response);
        }
    }
}