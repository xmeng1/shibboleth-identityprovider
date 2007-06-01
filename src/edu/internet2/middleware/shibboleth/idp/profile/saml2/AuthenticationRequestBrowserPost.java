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

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;

import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.security.SecurityPolicyException;

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
    
    /** SubjectConfirmation method for Web Browser SSO profile. */
    protected static final String SUBJ_CONF_METHOD_URI = "urn:oasis:namurn:oasis:names:tc:SAML:2.0:cm:bearer";
    
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
        
        // This method is called twice.
        // On the first time, there will be no AuthenticationRequestContext object. We redirect control to the
        // AuthenticationManager to authenticate the user. The AuthenticationManager then redirects control
        // back to this servlet. On the "return leg" connection, there will be a AuthenticationRequestContext object.
        
        HttpServletRequest req = (HttpServletRequest) request.getRawRequest();
        Object o = req.getSession().getAttribute(REQUEST_CONTEXT_SESSION_KEY);
        if (o != null && !(o instanceof AuthenticationRequestContext)) {
            log.error("SAML 2 AuthnRequest: Invalid session data found for AuthenticationRequestContext");
            throw new ProfileException("SAML 2 AuthnRequest: Invalid session data found for AuthenticationRequestContext");
        }
        
        if (o == null) {
            setupNewRequest(request, response);
        } else {
            
            AuthenticationRequestContext requestContext = (AuthenticationRequestContext)o;
            
            // clean up the HttpSession.
            requestContext.getHttpSession().removeAttribute(REQUEST_CONTEXT_SESSION_KEY);
            requestContext.getHttpSession().removeAttribute(LoginContext.LOGIN_CONTEXT_KEY);
            
            finishProcessingRequest(requestContext);
        }
    }
    
    /**
     * Begin processing a SAML 2.0 AuthnRequest.
     *
     * This ensures that the request is well-formed and that
     * appropriate metadata can be found for the SP.
     * Once these conditions are met, control is passed to
     * the AuthenticationManager to authenticate the user.
     * 
     * @param request The ProfileRequest.
     * @param response The ProfileResponse
     * 
     * @throws ProfileException On error.
     */
    protected void setupNewRequest(final ProfileRequest<ServletRequest> request,
            final ProfileResponse<ServletResponse> response) throws ProfileException {
        
        // If the user hasn't been authenticated, validate the AuthnRequest
        // and redirect to AuthenticationManager to authenticate the user.
        
        AuthenticationRequestContext requestContext = new AuthenticationRequestContext();
        
        requestContext.setProfileRequest(request);
        requestContext.setProfileResponse(response);
        
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
            
            requestContext.setAuthnRequest((AuthnRequest) samlObject);
            requestContext.setIssuer(decoder.getSecurityPolicy().getIssuer());
            validateRequestAgainstMetadata(requestContext);
            verifyAuthnRequest(requestContext);
            authenticateUser(requestContext);
            
        } catch (BindingException ex) {
            log.error("SAML 2 Authentication Request: Unable to decode SAML 2 Authentication Request", ex);
            throw new ProfileException(
                    "SAML 2 Authentication Request: Unable to decode SAML 2 Authentication Request", ex);
        } catch (SecurityPolicyException ex) {
            log.error("SAML 2 Authentication Request: Security error while decoding SAML 2 Authentication Request", ex);
        } catch (AuthenticationRequestException ex) {
            
            // AuthN failed. Send the failure status.
            requestContext.setResponse(buildResponse(requestContext.getAuthnRequest().getID(), 
                    new DateTime(), requestContext.getIssuer(), ex.getStatus()));
            encodeResponse(BINDING_URI, requestContext);
        }
    }
    
    /**
     * Process the "return leg" of a SAML 2 Authentication Request.
     *
     * This evaluates the AuthenticationManager's LoginContext and generates an Authentication Assertion.
     *
     * @param requestContext The context for this request.
     *
     * @throws ProfileException On error.
     */
    protected void finishProcessingRequest(final AuthenticationRequestContext requestContext) throws ProfileException {
        
        // The user has already been authenticated,
        // so generate an AuthenticationStatement.
        evaluateRequest(requestContext);
        encodeResponse(BINDING_URI, requestContext);
    }
    
}
