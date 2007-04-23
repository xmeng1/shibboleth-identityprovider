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
import org.opensaml.common.binding.MessageDecoder;
import org.opensaml.common.binding.MessageEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethAttributeRequestContext;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.saml2.AttributeQueryConfiguration;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * SAML 2.0 Attribute Query profile handler.
 */
public abstract class AbstractAttributeQuery extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AbstractAttributeQuery.class);

    /**
     * Gets the {@link AttributeQueryConfiguration} for the service provider identified by the given ID.
     * 
     * @param spId entity ID of the service provider
     * 
     * @return configuration for the given service provider or null
     */
    protected AttributeQueryConfiguration getAttributeQueryConfiguration(String spId) {
        return (AttributeQueryConfiguration) getProfileConfiguration(spId, AttributeQueryConfiguration.PROFILE_ID);
    }

    /**
     * Gets the attribute authority for the service provider identified by the given ID.
     * 
     * @param spId entity ID of the service provider
     * 
     * @return attribute authority for the service provider or null
     */
    protected SAML2AttributeAuthority getAttributeAuthority(String spId) {
        AttributeQueryConfiguration config = getAttributeQueryConfiguration(spId);
        if (config != null) {
            return config.getAttributeAuthority();
        }

        return null;
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response)
            throws ProfileException {
        MessageDecoder<ServletRequest> decoder = getMessageDecoder(request);
        populateMessageDecoder(decoder);
        decoder.setRequest(request.getRawRequest());

        // get message from the decoder
        AttributeQuery attributeQuery = null;
        try {
            decoder.decode();
            if (log.isDebugEnabled()) {
                log.debug("decoded http servlet request");
            }
            attributeQuery = (AttributeQuery) decoder.getSAMLMessage();
        } catch (BindingException e) {
            log.error("Error decoding attribute query message", e);
            throw new ProfileException("Error decoding attribute query message");
        }

        String spEntityId = attributeQuery.getIssuer().getValue();
        String userSessionId = getUserSessionId(request);
        Session userSession = getSessionManager().getSession(userSessionId);
        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(spEntityId);
        AttributeQueryConfiguration profileConfig = getAttributeQueryConfiguration(spEntityId);
        DateTime issueInstant = new DateTime();

        ShibbolethAttributeRequestContext attributeRequestContext = buildAttributeRequestContext(spEntityId,
                userSession, request);

        // resolve attributes with the attribute authority
        AttributeStatement attributeStatement = null;
        try {
            SAML2AttributeAuthority attributeAuthority = profileConfig.getAttributeAuthority();
            attributeStatement = attributeAuthority.performAttributeQuery(attributeRequestContext);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes", e);
            throw new ProfileException("Error resolving attributes", e);
        }

        // construct attribute response
        Response samlResponse = getResponseBuilder().buildObject();
        populateStatusResponse(samlResponse, issueInstant, attributeQuery, rpConfig);

        Assertion assertion = buildAssertion(issueInstant, rpConfig, profileConfig);
        assertion.getAttributeStatements().add(attributeStatement);
        samlResponse.getAssertions().add(assertion);

        signAssertion(assertion, rpConfig, profileConfig);
        signResponse(samlResponse, rpConfig, profileConfig);

        MessageEncoder<ServletResponse> messageEncoder = getMessageEncoder(response);
        populateMessageEncoder(messageEncoder);
        messageEncoder.setRelyingParty(spEntityId);
        messageEncoder.setSAMLMessage(samlResponse);

        try {
            messageEncoder.encode();
        } catch (BindingException e) {
            // TODO
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
}