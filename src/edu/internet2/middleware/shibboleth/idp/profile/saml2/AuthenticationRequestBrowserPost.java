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
import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

/**
 * Browser POST binding for SAML 2 AuthenticationRequest.
 */
public class AuthenticationRequestBrowserPost extends AbstractAuthenticationRequest {
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(AuthenticationRequestBrowserPost.class);
    
    /** SAML 2 Profile ID. */
    protected static final String PROFILE_ID = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser";
    
    /** SAML 2 Binding URI. */
    protected static final String BINDING_URI = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    
    /** Constructor. */
    public AuthenticationRequestBrowserPost() {
        super();
    }
    
    /** {@inheritDoc} */
    public String getProfileId() {
        return PROFILE_ID;
    }
    
    /** {@inheritDoc} */
    public void processRequest(final ProfileRequest<ServletRequest> request,
            final ProfileResponse<ServletResponse> response)
            throws ProfileException {
        
        // Only http servlets are supported for now.
        if (!(request.getRawRequest() instanceof HttpServletRequest)) {
            log.error("Received a non-HTTP request");
            throw new ProfileException("Received a non-HTTP request");
        }
        
        HttpServletRequest httpRequest = (HttpServletRequest) request.getRawRequest();
        HttpServletResponse httpResponse = (HttpServletResponse) response.getRawResponse();
        HttpSession httpSession = httpRequest.getSession();
        
        AuthnRequest authnRequest = null;
        String issuer = null;
        MetadataProvider metadataProvider = null;
        RelyingPartyConfiguration relyingParty = null;
        SSOConfiguration ssoConfig = null;
        SPSSODescriptor spDescriptor = null;
        
        
        // If the user hasn't been authenticated, validate the AuthnRequest
        // and redirect to AuthenticationManager to authenticate the user.
        if (!hasUserAuthenticated(httpSession)) {
            
            try {
                // decode the AuthnRequest
                MessageDecoder<ServletRequest> decoder = getMessageDecoderFactory().getMessageDecoder(BINDING_URI);
                if (decoder == null) {
                    log.error("SAML 2 AuthnRequest: No MessageDecoder registered for " + BINDING_URI);
                    throw new ProfileException("SAML 2 AuthnRequest: No MessageDecoder registered for " + BINDING_URI);
                }
                
                decoder.setMetadataProvider(getMetadataProvider());
                populateMessageDecoder(decoder);
                decoder.decode();
                
                SAMLObject samlObject = decoder.getSAMLMessage();
                if (!(samlObject instanceof AuthnRequest)) {
                    log.error("SAML 2 AuthnRequest: Received message is not a SAML 2 Authentication Request");
                    throw new ProfileException("SAML 2 AuthnRequest: Received message is not a SAML 2 Authentication Request");
                }
                
                authnRequest = (AuthnRequest) samlObject;
                issuer = decoder.getSecurityPolicy().getIssuer();
                
                // check that we have metadata for the RP
                metadataProvider = getRelyingPartyConfigurationManager().getMetadataProvider();
                relyingParty = getRelyingPartyConfigurationManager().getRelyingPartyConfiguration(issuer);
                ssoConfig = (SSOConfiguration) relyingParty.getProfileConfigurations().get(SSOConfiguration.PROFILE_ID);
                
                try {
                    spDescriptor = metadataProvider.getEntityDescriptor(
                            relyingParty.getRelyingPartyId()).getSPSSODescriptor(
                            SAML20_PROTOCOL_URI);
                } catch (MetadataProviderException ex) {
                    log.error(
                            "SAML 2 Authentication Request: Unable to locate metadata for SP "
                            + issuer + " for protocol " + SAML20_PROTOCOL_URI, ex);
                    throw new ProfileException("SAML 2 Authentication Request: Unable to locate metadata for SP "
                            + issuer + " for protocol " + SAML20_PROTOCOL_URI, ex);
                }
                
                if (spDescriptor == null) {
                    log.error("SAML 2 Authentication Request: Unable to locate metadata for SP "
                            + issuer + " for protocol " + SAML20_PROTOCOL_URI);
                    throw new ProfileException("SAML 2 Authentication Request: Unable to locate metadata for SP "
                            + issuer + " for protocol " + SAML20_PROTOCOL_URI);
                }
                
                verifyAuthnRequest(authnRequest, issuer, relyingParty, httpSession);
                storeRequestData(httpSession, authnRequest, issuer, relyingParty, ssoConfig, spDescriptor);
                authenticateUser(authnRequest, httpSession, httpRequest, httpResponse);
                
            } catch (BindingException ex) {
                log.error("SAML 2 Authentication Request: Unable to decode SAML 2 Authentication Request", ex);
                throw new ProfileException(
                        "SAML 2 Authentication Request: Unable to decode SAML 2 Authentication Request", ex);
            } catch (AuthenticationRequestException ex) {
                
                // AuthN failed. Send the failure status.
                retrieveRequestData(httpSession, authnRequest, issuer, relyingParty, ssoConfig, spDescriptor);
                Response failureResponse = buildResponse(authnRequest.getID(), new DateTime(), issuer, ex.getStatus());
                encodeResponse(BINDING_URI, response, failureResponse, relyingParty, ssoConfig, spDescriptor);
            } 
        }
        
        // The user has already been authenticated,
        // so generate an AuthenticationStatement.
        retrieveRequestData(httpSession, authnRequest, issuer, relyingParty, ssoConfig, spDescriptor);
        Response samlResponse = evaluateRequest(authnRequest, issuer, httpSession, relyingParty, ssoConfig, spDescriptor);
        encodeResponse(BINDING_URI, response, samlResponse, relyingParty, ssoConfig, spDescriptor);
    }
}
