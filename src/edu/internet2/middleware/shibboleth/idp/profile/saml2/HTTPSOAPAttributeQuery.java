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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.common.binding.BindingException;
import org.opensaml.saml2.binding.HTTPSOAP11Decoder;
import org.opensaml.saml2.binding.HTTPSOAP11Encoder;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.encryption.EncryptionException;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethAttributeRequestContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;

/**
 * SAML 2.0 SOAP Attribute Query profile handler.
 */
public class HTTPSOAPAttributeQuery extends AbstractAttributeQuery {

    /** Class logger. */
    private static Logger log = Logger.getLogger(HTTPSOAPAttributeQuery.class);

    /**
     * This creates a new http soap attribute query.
     * 
     * @param ar <code>AttributeResolver</code>
     */
    public HTTPSOAPAttributeQuery(AttributeResolver<ShibbolethAttributeRequestContext> ar) {
        super(ar);
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response)
            throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("begin processRequest");
        }

        // check that request/response is of proper type
        if (!(request.getRawRequest() instanceof HttpServletRequest)) {
            throw new ProfileException(HTTPSOAPAttributeQuery.class.getName() + " can only process requests of type "
                    + HttpServletRequest.class.getName());
        } else if (!(response.getRawResponse() instanceof HttpServletResponse)) {
            throw new ProfileException(HTTPSOAPAttributeQuery.class.getName() + " can only process responses of type "
                    + HttpServletResponse.class.getName());
        }

        // create decoder
        HTTPSOAP11Decoder decoder = new HTTPSOAP11Decoder();
        decoder.setMetadataProvider(getMetadataProvider());
        // TODO decoder.setSecurityPolicy(policy);
        // TODO decoder.setTrustEngine(newEngine);

        // get message from the decoder
        org.opensaml.saml2.core.AttributeQuery message = null;
        try {
            decoder.setRequest((HttpServletRequest) request.getRawRequest());
            decoder.decode();
            if (log.isDebugEnabled()) {
                log.debug("decoded http servlet request");
            }
            message = (org.opensaml.saml2.core.AttributeQuery) decoder.getSAMLMessage();
        } catch (BindingException e) {
            log.error("Error decoding attribute query message", e);
            throw new ProfileException("Error decoding attribute query message");
        }

        // get the provider id from the message issuer
        String providerId = message.getIssuer().getSPProvidedID();

        // TODO get user data from the session, need sessionId
        // ?? getSessionManager().getSession(null).getServicesInformation().get(0);
        ServiceInformation serviceInformation = null;
        String principalName = serviceInformation.getSubjectNameID().getSPProvidedID();
        String authenticationMethod = serviceInformation.getAuthenticationMethod().getAuthenticationMethod();

        // create attribute request for the attribute authority
        ShibbolethAttributeRequestContext requestContext = null;
        try {
            requestContext = new ShibbolethAttributeRequestContext(getMetadataProvider(),
                    getRelyingPartyConfiguration(providerId));
            requestContext.setPrincipalName(principalName);
            requestContext.setPrincipalAuthenticationMethod(authenticationMethod);
            requestContext.setRequest(request.getRawRequest());
        } catch (MetadataProviderException e) {
            log.error("Error creating ShibbolethAttributeRequestContext", e);
            throw new ProfileException("Error retrieving metadata", e);
        }

        // resolve attributes with the attribute authority
        AttributeStatement statement = null;
        try {
            statement = getAttributeAuthority().performAttributeQuery(requestContext);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes", e);
            throw new ProfileException("Error resolving attributes", e);
        }

        // construct attribute response
        Response samlResponse = null;
        try {
            ProfileResponseContext profileResponse = new ProfileResponseContext(request, message);
            profileResponse.setIssuer(decoder.getSecurityPolicy().getIssuer().toString());
            profileResponse.setDestination(request.getRawRequest().getRemoteHost());
            profileResponse.setAttributeStatement(statement);
            samlResponse = buildResponse(profileResponse);
        } catch (EncryptionException e) {
            log.error("Error encrypting SAML response", e);
            throw new ProfileException("Error encrypting SAML response", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("built saml2 response: " + samlResponse);
        }

        // encode response
        try {
            HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
            encoder.setMetadataProvider(getMetadataProvider());
            encoder.setRelyingParty(getRelyingPartyConfiguration(providerId).getRelyingPartyId());
            encoder.setResponse((HttpServletResponse) response.getRawResponse());
            encoder.setSAMLMessage(samlResponse);
            encoder.encode();
        } catch (BindingException e) {
            log.error("Error encoding attribute query response", e);
            throw new ProfileException("Error encoding attribute query response", e);
        }
    }
}
