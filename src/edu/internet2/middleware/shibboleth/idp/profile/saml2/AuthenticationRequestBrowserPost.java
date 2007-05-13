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
import javax.servlet.ServletException;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.saml2.SSOConfiguration;

import org.apache.log4j.Logger;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.metadata.SPSSODescriptor;

/**
 * Browser POST binding for SAML 2 AuthenticationRequest.
 */
public class AuthenticationRequestBrowserPost extends AbstractAuthenticationRequest {
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(AuthenticationRequestBrowserPost.class);
    
    /** Constructor. */
    public AuthenticationRequestBrowserPost() {
        super();
    }
    
    /** {@inheritDoc} */
    public void processRequest(final ProfileRequest<ServletRequest> request,
            final ProfileResponse<ServletResponse> response)
            throws ProfileException {
        
        // Only http servlets are supported for now.
        if (!(request.getRawRequest() instanceof HttpServletRequest)) {
            log.error("Received a non-HTTP request");
            throw new ServletException("Received a non-HTTP request");
        }
        
        HttpServletRequest httpReq = (HttpServletRequest) request.getRawRequest();
        HttpServletResponse httpResp = (HttpServletResponse) response.getRawResponse();
        HttpSession httpSession = httpReq.getSession();
        
        AuthnRequest authnRequest;
        Issuer issuer;
        RelyingPartyConfiguration relyingParty;
        SSOConfiguration ssoConfig;
        SPSSODescriptor spDescriptor;
        
        // If the user hasn't been authenticated, validate the AuthnRequest
        // and redirect to AuthenticationManager to authenticate the user.
        if (!hasUserAuthenticated(httpSession)) {
            
            try {
                MessageDecoder<HttpServletRequest> decoder = new HTTPPostDecoder();
                decoder.setMetadataProvider(getRelyingPartyConfigurationManager().getMetadataProvider());
                // decoder.setSecurityPolicy(??);
                // decoder.setTrustEngine(??);
                decoder.setRequest(httpReq);
                decoder.decode();
                SAMLObject samlObject = decoder.getSAMLMessage();
                if (!(samlObject instanceof AuthnRequest)) {
                    log.error("SAML 2 AuthnRequest: Received message is not a SAML 2 Authentication Request");
                    throw new ProfileException("SAML 2 AuthnRequest: Received message is not a SAML 2 Authentication Request");
                }
                
                authnRequest = (AuthnRequest) samlObject;
                issuer = (Issuer) decoder.getSecurityPolicy().getIssuer();
                
                if (!findMetadataForSSORequest(issuer, relyingParty, ssoConfig, spDescriptor)) {
                    throw new ProfileException(
                            "SAML 2 AuthnRequest: Unable to locate metadata for issuer: "
                            + issuer.getSPProvidedID());
                }
                
                verifyAuthnRequest(authnRequest, issuer, relyingParty, httpSession);
                storeRequestData(httpSession, authnRequest, issuer, relyingParty, ssoConfig, spDescriptor);
                authenticateUser(authnRequest, httpSession, httpReq, httpResp);
                
            } catch (BindingException ex) {
                log.error("SAML 2 Authentication Request: Unable to decode SAML 2 Authentication Request", ex);
                throw new ProfileException(
                        "SAML 2 Authentication Request: Unable to decode SAML 2 Authentication Request", ex);
            } catch (AuthenticationRequestException ex) {
                // XXX: todo: generate and send the error, with a REQUEST_URI
                // failure.
            }
        }
        
        // The user has already been authenticated,
        // so generate an AuthenticationStatement.
        retrieveRequestData(httpSession, authnRequest, issuer, relyingParty, ssoConfig, spDescriptor);
        Response samlResponse = evaluateRequest(authnRequest, issuer, httpSession, relyingParty, ssoConfig, spDescriptor);
        encodeResponse(response, samlResponse, relyingParty, ssoConfig, spDescriptor);
    }
    
    protected void encodeResponse(final ProfileResponse response,
            final Response samlResponse,
            final RelyingPartyConfiguration relyingParty,
            final SSOConfiguration ssoConfig, final SPSSODescriptor spDescriptor) {
        // xxx: todo
    }
}
