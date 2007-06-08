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

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.common.binding.encoding.MessageEncoder;
import org.opensaml.common.binding.security.SAMLSecurityPolicy;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;

/**
 * SAML 2.0 authentication request profile handler.
 */
public class SSOProfileHandler extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private final Logger log = Logger.getLogger(SSOProfileHandler.class);

    /** Builder of AuthnStatement objects. */
    private SAMLObjectBuilder<AuthnStatement> authnStatementBuilder;

    /** Builder of AuthnContext objects. */
    private SAMLObjectBuilder<AuthnContext> authnContextBuilder;

    /** Builder of AuthnContextClassRef objects. */
    private SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder;

    /** Builder of AuthnContextDeclRef objects. */
    private SAMLObjectBuilder<AuthnContextDeclRef> authnContextDeclRefBuilder;

    /** URL of the authentication manager servlet. */
    private String authenticationManagerPath;

    /** URI of request decoder. */
    private String decodingBinding;

    /** URI of response encoder. */
    private String encodingBinding;

    /**
     * Constructor.
     * 
     * @param authnManagerPath path to the authentication manager servlet
     * @param decoder URI of the request decoder to use
     * @param encoder URI of the response encoder to use
     */
    @SuppressWarnings("unchecked")
    public SSOProfileHandler(String authnManagerPath, String decoder, String encoder) {
        super();

        if (authnManagerPath == null || decoder == null || encoder == null) {
            throw new IllegalArgumentException("AuthN manager path, decoding, encoding bindings URI may not be null");
        }
        
        authenticationManagerPath = authnManagerPath;
        decodingBinding = decoder;
        encodingBinding = encoder;

        authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) getBuilderFactory().getBuilder(
                AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) getBuilderFactory().getBuilder(
                AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) getBuilderFactory().getBuilder(
                AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextDeclRefBuilder = (SAMLObjectBuilder<AuthnContextDeclRef>) getBuilderFactory().getBuilder(
                AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml2:request:authentication";
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response)
            throws ProfileException {

        HttpSession httpSession = ((HttpServletRequest) request.getRawRequest()).getSession(true);
        if (httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY) == null) {
            performAuthentication(request, response);
        } else {
            completeAuthenticationRequest(request, response);
        }
    }

    /**
     * Creates a {@link Saml2LoginContext} an sends the request off to the AuthenticationManager to begin the
     * process of authenticating the user.
     * 
     * @param request current request
     * @param response current response
     * 
     * @throws ProfileException thrown if there is a problem creating the login context and transferring control to the
     *             authentication manager
     */
    protected void performAuthentication(ProfileRequest<ServletRequest> request,
            ProfileResponse<ServletResponse> response) throws ProfileException {
        HttpServletRequest httpRequest = (HttpServletRequest) request.getRawRequest();

        AuthnRequest authnRequest = null;
        try {
            MessageDecoder<ServletRequest> decoder = decodeRequest(request);
            SAMLSecurityPolicy<ServletRequest> securityPolicy = decoder.getSecurityPolicy();

            String relyingParty = securityPolicy.getIssuer();
            authnRequest = (AuthnRequest) decoder.getSAMLMessage();

            Saml2LoginContext loginContext = new Saml2LoginContext(relyingParty, authnRequest);
            loginContext.setProfileHandlerURL(httpRequest.getRequestURI());

            HttpSession httpSession = httpRequest.getSession();
            httpSession.setAttribute(Saml2LoginContext.LOGIN_CONTEXT_KEY, loginContext);
            RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(authenticationManagerPath);
            dispatcher.forward(httpRequest, response.getRawResponse());
        } catch (MarshallingException e) {
            log.error("Unable to marshall authentication request context");
            throw new ProfileException("Unable to marshall authentication request context", e);
        } catch (IOException ex) {
            log.error("Error forwarding SAML 2 AuthnRequest " + authnRequest.getID() + " to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding SAML 2 AuthnRequest " + authnRequest.getID()
                    + " to AuthenticationManager", ex);
        } catch (ServletException ex) {
            log.error("Error forwarding SAML 2 AuthnRequest " + authnRequest.getID() + " to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding SAML 2 AuthnRequest " + authnRequest.getID()
                    + " to AuthenticationManager", ex);
        }
    }

    /**
     * Creates a response to the {@link AuthnRequest} and sends the user, with response in tow, back to the relying
     * party after they've been authenticated.
     * 
     * @param request current request
     * @param response current response
     * 
     * @throws ProfileException thrown if the response can not be created and sent back to the relying party
     */
    protected void completeAuthenticationRequest(ProfileRequest<ServletRequest> request,
            ProfileResponse<ServletResponse> response) throws ProfileException {

        HttpSession httpSession = ((HttpServletRequest) request.getRawRequest()).getSession(true);
        Saml2LoginContext loginContext = (Saml2LoginContext) httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        AuthenticationRequestContext requestContext = buildRequestContext(loginContext, request, response);

        Response samlResponse;
        try {
            if (!loginContext.getAuthenticationOK()) {
                requestContext
                        .setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI, null));
                throw new ProfileException("User failed authentication");
            }

            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAuthnStatement(requestContext));
            statements.add(buildAttributeStatement(requestContext));

            Subject assertionSubject = buildSubject(requestContext, "urn:oasis:names:tc:SAML:2.0:cm:bearer");

            samlResponse = buildResponse(requestContext, assertionSubject, statements);
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext);
        }

        requestContext.setSamlResponse(samlResponse);
        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Creates an appropriate message decoder, populates it, and decodes the incoming request.
     * 
     * @param request current request
     * 
     * @return message decoder containing the decoded message and other stateful information
     * 
     * @throws ProfileException thrown if the incomming message failed decoding
     */
    protected MessageDecoder<ServletRequest> decodeRequest(ProfileRequest<ServletRequest> request)
            throws ProfileException {
        MessageDecoder<ServletRequest> decoder = getMessageDecoderFactory().getMessageDecoder(decodingBinding);
        if (decoder == null) {
            log.error("No request decoder was registered for binding type: " + decodingBinding);
            throw new ProfileException("No request decoder was registered for binding type: " + decodingBinding);
        }

        populateMessageDecoder(decoder);
        decoder.setRequest(request.getRawRequest());
        try {
            decoder.decode();
            return decoder;
        } catch (BindingException e) {
            log.error("Error decoding authentication request message", e);
            throw new ProfileException("Error decoding authentication request message", e);
        } catch (SecurityPolicyException e) {
            log.error("Message did not meet security policy requirements", e);
            throw new ProfileException("Message did not meet security policy requirements", e);
        }
    }

    /**
     * Creates an authentication request context from the current environmental information.
     * 
     * @param loginContext current login context
     * @param request current request
     * @param response current response
     * 
     * @return created authentication request context
     * 
     * @throws ProfileException thrown if there is a problem creating the context
     */
    protected AuthenticationRequestContext buildRequestContext(Saml2LoginContext loginContext,
            ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response) throws ProfileException {
        AuthenticationRequestContext requestContext = new AuthenticationRequestContext(request, response);

        try {
            String relyingPartyId = loginContext.getRelyingPartyId();
            AuthnRequest authnRequest = loginContext.getAuthenticationRequest();

            requestContext.setRelyingPartyId(relyingPartyId);

            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
            requestContext.setRelyingPartyConfiguration(rpConfig);

            requestContext.setRelyingPartyRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

            requestContext.setAssertingPartyId(requestContext.getRelyingPartyConfiguration().getProviderId());

            requestContext.setAssertingPartyRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

            requestContext.setProfileConfiguration((SSOConfiguration) rpConfig
                    .getProfileConfiguration(SSOConfiguration.PROFILE_ID));

            requestContext.setSamlRequest(authnRequest);

            return requestContext;
        } catch (UnmarshallingException e) {
            log.error("Unable to unmarshall authentication request context");
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Error recovering request state"));
            throw new ProfileException("Error recovering request state", e);
        }
    }

    /**
     * Creates an authentication statement for the current request.
     * 
     * @param requestContext current request context
     * 
     * @return constructed authentication statement
     */
    protected AuthnStatement buildAuthnStatement(AuthenticationRequestContext requestContext) {
        Saml2LoginContext loginContext = requestContext.getLoginContext();

        AuthnContext authnContext = buildAuthnContext(requestContext);

        AuthnStatement statement = authnStatementBuilder.buildObject();
        statement.setAuthnContext(authnContext);
        statement.setAuthnInstant(loginContext.getAuthenticationInstant());

        // TODO
        statement.setSessionIndex(null);

        if (loginContext.getAuthenticationDuration() > 0) {
            statement.setSessionNotOnOrAfter(loginContext.getAuthenticationInstant().plus(
                    loginContext.getAuthenticationDuration()));
        }

        // TODO
        statement.setSubjectLocality(null);

        return statement;
    }

    /**
     * Creates an {@link AuthnContext} for a succesful authentication request.
     * 
     * @param requestContext current request
     * 
     * @return the built authn context
     */
    protected AuthnContext buildAuthnContext(AuthenticationRequestContext requestContext) {
        AuthnContext authnContext = authnContextBuilder.buildObject();

        Saml2LoginContext loginContext = requestContext.getLoginContext();
        AuthnRequest authnRequest = requestContext.getSamlRequest();
        RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
        if (requestedAuthnContext != null) {
            if (requestedAuthnContext.getAuthnContextClassRefs() != null) {
                for (AuthnContextClassRef classRef : requestedAuthnContext.getAuthnContextClassRefs()) {
                    if (classRef.getAuthnContextClassRef().equals(loginContext.getAuthenticationMethod())) {
                        AuthnContextClassRef ref = authnContextClassRefBuilder.buildObject();
                        ref.setAuthnContextClassRef(loginContext.getAuthenticationMethod());
                        authnContext.setAuthnContextClassRef(ref);
                    }
                }
            } else if (requestedAuthnContext.getAuthnContextDeclRefs() != null) {
                for (AuthnContextDeclRef declRef : requestedAuthnContext.getAuthnContextDeclRefs()) {
                    if (declRef.getAuthnContextDeclRef().equals(loginContext.getAuthenticationMethod())) {
                        AuthnContextDeclRef ref = authnContextDeclRefBuilder.buildObject();
                        ref.setAuthnContextDeclRef(loginContext.getAuthenticationMethod());
                        authnContext.setAuthnContextDeclRef(ref);
                    }
                }
            }
        } else {
            AuthnContextDeclRef ref = authnContextDeclRefBuilder.buildObject();
            ref.setAuthnContextDeclRef(loginContext.getAuthenticationMethod());
            authnContext.setAuthnContextDeclRef(ref);
        }

        return authnContext;
    }

    /**
     * Encodes the request's SAML response and writes it to the servlet response.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if no message encoder is registered for this profiles binding
     */
    protected void encodeResponse(AuthenticationRequestContext requestContext) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Encoding response to SAML request " + requestContext.getSamlRequest().getID()
                    + " from relying party " + requestContext.getRelyingPartyId());
        }
        MessageEncoder<ServletResponse> encoder = getMessageEncoderFactory().getMessageEncoder(encodingBinding);
        if (encoder == null) {
            log.error("No response encoder was registered for binding type: " + encodingBinding);
            throw new ProfileException("No response encoder was registered for binding type: " + encodingBinding);
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

    /**
     * Represents the internal state of a SAML 2.0 Authentiation Request while it's being processed by the IdP.
     */
    protected class AuthenticationRequestContext extends
            SAML2ProfileRequestContext<AuthnRequest, Response, SSOConfiguration> {

        /** Current login context. */
        private Saml2LoginContext loginContext;

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public AuthenticationRequestContext(ProfileRequest<ServletRequest> request,
                ProfileResponse<ServletResponse> response) {
            super(request, response);
        }

        /**
         * Gets the current login context.
         * 
         * @return current login context
         */
        public Saml2LoginContext getLoginContext() {
            return loginContext;
        }

        /**
         * Sets the current login context.
         * 
         * @param context current login context
         */
        public void setLoginContext(Saml2LoginContext context) {
            loginContext = context;
        }
    }
}