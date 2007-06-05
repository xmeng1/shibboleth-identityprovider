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
import java.util.Map;

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
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.security.SecurityPolicyException;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethSAMLAttributeRequestContext;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AttributeQueryConfiguration;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

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

            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAttributeStatement(requestContext));

            samlResponse = buildResponse(requestContext, statements);
        } catch (SecurityPolicyException e) {
            samlResponse = buildErrorResponse(requestContext, StatusCode.REQUESTER, StatusCode.REQUEST_DENIED, e
                    .getMessage());
        } catch (AttributeRequestException e) {
            samlResponse = buildErrorResponse(requestContext, StatusCode.RESPONDER, null, e.getMessage());
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext, StatusCode.RESPONDER, StatusCode.REQUEST_DENIED, e
                    .getMessage());
        }
    }

    /**
     * Decodes the message in the request and adds it to the request context.
     * 
     * @param requestContext request context contianing the request to decode
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     * @throws SecurityPolicyException thrown if the message was decoded properly but did not meet the necessary
     *             security policy requirements
     */
    protected void decodeRequest(AttributeQueryContext requestContext) throws ProfileException, SecurityPolicyException {
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
            throw new ProfileException("Error decoding attribute query message");
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
     * Executes a query for attributes and builds a SAML attribute statement from the results.
     * 
     * @param requestContext current request context
     * 
     * @return attribute statement resulting from the query
     * 
     * @throws ProfileException thrown if there is a problem making the query
     * @throws AttributeRequestException thrown if there is a problem resolving attributes
     */
    protected AttributeStatement buildAttributeStatement(AttributeQueryContext requestContext) throws ProfileException,
            AttributeRequestException {

        if (log.isDebugEnabled()) {
            log.debug("Creating attribute statement in response to SAML request  from relying party "
                    + requestContext.getRelyingPartyId());
        }

        try {
            AttributeQueryConfiguration profileConfiguration = requestContext.getProfileConfiguration();
            if (profileConfiguration == null) {
                log.error("No SAML 1 attribute query profile configuration is defined for relying party: "
                        + requestContext.getRelyingPartyId());
                throw new AttributeRequestException("SAML 1 attribute query is not configured for this relying party");
            }

            SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

            ShibbolethSAMLAttributeRequestContext<NameIdentifier, AttributeQuery> attributeRequestContext = buildAttributeRequestContext(requestContext);

            if (log.isDebugEnabled()) {
                log.debug("Resolving principal name for subject of SAML request from relying party "
                        + requestContext.getRelyingPartyId());
            }
            String principal = attributeAuthority.getPrincipal(attributeRequestContext);
            requestContext.setPrincipalName(principal);

            if (log.isDebugEnabled()) {
                log.debug("Resolving attributes for principal " + principal + " of SAML request from relying party "
                        + requestContext.getRelyingPartyId());
            }
            Map<String, BaseAttribute> principalAttributes = attributeAuthority
                    .getAttributes(buildAttributeRequestContext(requestContext));

            requestContext.setPrincipalAttributes(principalAttributes);

            AttributeStatement statment = attributeAuthority.buildAttributeStatement(requestContext.getSamlRequest(),
                    principalAttributes.values());

            Subject statementSubject = buildSubject(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches");
            statment.setSubject(statementSubject);

            return statment;
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes for SAML request from relying party "
                    + requestContext.getRelyingPartyId(), e);
            throw e;
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
            AttributeQueryContext requestContext) {

        ShibbolethSAMLAttributeRequestContext<NameIdentifier, AttributeQuery> queryContext = new ShibbolethSAMLAttributeRequestContext<NameIdentifier, AttributeQuery>(
                getMetadataProvider(), requestContext.getRelyingPartyConfiguration(), requestContext.getSamlRequest());

        queryContext.setAttributeRequester(requestContext.getAssertingPartyId());
        queryContext.setPrincipalName(requestContext.getPrincipalName());
        queryContext.setProfileConfiguration(requestContext.getProfileConfiguration());
        queryContext.setRequest(requestContext.getProfileRequest());

        Session userSession = getSessionManager().getSession(getUserSessionId(requestContext.getProfileRequest()));
        if (userSession != null) {
            queryContext.setUserSession(userSession);
            ServiceInformation serviceInfo = userSession.getServiceInformation(requestContext.getRelyingPartyId());
            if (serviceInfo != null) {
                String principalAuthenticationMethod = serviceInfo.getAuthenticationMethod().getAuthenticationMethod();

                requestContext.setPrincipalAuthenticationMethod(principalAuthenticationMethod);
                queryContext.setPrincipalAuthenticationMethod(principalAuthenticationMethod);
            }
        }

        return queryContext;
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