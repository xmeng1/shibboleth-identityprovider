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
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.common.binding.encoding.MessageEncoder;
import org.opensaml.common.binding.security.SAMLSecurityPolicy;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.security.SecurityPolicyException;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethSAMLAttributeRequestContext;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AttributeQueryConfiguration;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * SAML 2.0 Attribute Query profile handler.
 */
public class AttributeQueryProfileHandler extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AttributeQueryProfileHandler.class);

    /** SAML binding URI. */
    private static final String BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml2:query:attribute";
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response)
            throws ProfileException {

        AttributeQueryContext requestContext = new AttributeQueryContext(request, response);

        Response samlResponse;
        try {
            decodeRequest(requestContext);

            // populate request context with information from decoded message
            SAMLSecurityPolicy securityPolicy = requestContext.getMessageDecoder().getSecurityPolicy();
            requestContext.setRelyingPartyId(securityPolicy.getIssuer());
            requestContext
                    .setRelyingPartyConfiguration(getRelyingPartyConfiguration(requestContext.getRelyingPartyId()));
            requestContext.setRelyingPartyRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setAssertingPartyId(requestContext.getRelyingPartyConfiguration().getProviderId());
            requestContext.setAssertingPartyRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setProfileConfiguration((AttributeQueryConfiguration) getProfileConfiguration(requestContext
                    .getRelyingPartyId(), AttributeQueryConfiguration.PROFILE_ID));
            requestContext.setSamlRequest((AttributeQuery) requestContext.getMessageDecoder().getSAMLMessage());

            // TODO principal

            // create the SAML attribute statement
            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAttributeStatement(requestContext));
            
            //TODO NameID
            Subject assertionSubject = buildSubject(requestContext, "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");

            // create the SAML response
            samlResponse = buildResponse(requestContext, assertionSubject, statements);
        } catch (SecurityPolicyException e) {
            samlResponse = buildErrorResponse(requestContext, StatusCode.REQUESTER_URI, StatusCode.REQUEST_DENIED_URI,
                    e.getMessage());
        } catch (AttributeRequestException e) {
            samlResponse = buildErrorResponse(requestContext, StatusCode.RESPONDER_URI,
                    StatusCode.INVALID_ATTR_NAME_VALUE_URI, e.getMessage());
        }

        requestContext.setSamlResponse(samlResponse);

        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
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
        MessageDecoder<ServletRequest> decoder = getMessageDecoderFactory().getMessageDecoder(BINDING);
        if (decoder == null) {
            throw new ProfileException("No request decoder was registered for binding type: " + BINDING);
        }

        super.populateMessageDecoder(decoder);
        decoder.setRequest(requestContext.getProfileRequest().getRawRequest());
        requestContext.setMessageDecoder(decoder);

        try {
            decoder.decode();
            if (log.isDebugEnabled()) {
                log.debug("decoded http servlet request");
            }
        } catch (BindingException e) {
            log.error("Error decoding attribute query message", e);
            throw new ProfileException("Error decoding attribute query message");
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

        try {
            AttributeQueryConfiguration profileConfiguration = requestContext.getProfileConfiguration();
            if (profileConfiguration == null) {
                log.error("No SAML 2 attribute query profile configuration is defined for relying party: "
                        + requestContext.getRelyingPartyId());
                throw new AttributeRequestException("SAML 2 attribute query is not configured for this relying party");
            }

            SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

            Map<String, BaseAttribute> principalAttributes = attributeAuthority
                    .getAttributes(buildAttributeRequestContext(requestContext));

            requestContext.setPrincipalAttributes(principalAttributes);

            return attributeAuthority.buildAttributeStatement(requestContext.getSamlRequest(), principalAttributes
                    .values());
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes", e);
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
    protected ShibbolethSAMLAttributeRequestContext<NameID, AttributeQuery> buildAttributeRequestContext(
            AttributeQueryContext requestContext) {

        ShibbolethSAMLAttributeRequestContext<NameID, AttributeQuery> queryContext = new ShibbolethSAMLAttributeRequestContext<NameID, AttributeQuery>(
                getMetadataProvider(), requestContext.getRelyingPartyConfiguration(), requestContext.getSamlRequest());

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

        queryContext.setProfileConfiguration(requestContext.getProfileConfiguration());
        queryContext.setRequest(requestContext.getProfileRequest());

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
        MessageEncoder<ServletResponse> encoder = getMessageEncoderFactory().getMessageEncoder(BINDING);
        if (encoder == null) {
            throw new ProfileException("No response encoder was registered for binding type: " + BINDING);
        }

        super.populateMessageEncoder(encoder);
        encoder.setResponse(requestContext.getProfileResponse().getRawResponse());
        encoder.setSamlMessage(requestContext.getSamlResponse());
        requestContext.setMessageEncoder(encoder);
    }

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryContext extends
            SAML2ProfileRequestContext<AttributeQuery, Response, AttributeQueryConfiguration> {

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