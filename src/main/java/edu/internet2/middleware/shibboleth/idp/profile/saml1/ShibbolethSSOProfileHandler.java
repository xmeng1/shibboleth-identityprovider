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

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectLocality;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.ShibbolethConstants;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.ShibbolethSSOConfiguration;
import edu.internet2.middleware.shibboleth.common.util.HttpHelper;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.ShibbolethSSOLoginContext;

/** Shibboleth SSO request profile handler. */
public class ShibbolethSSOProfileHandler extends AbstractSAML1ProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ShibbolethSSOProfileHandler.class);

    /** Builder of AuthenticationStatement objects. */
    private SAMLObjectBuilder<AuthenticationStatement> authnStatementBuilder;

    /** Builder of SubjectLocality objects. */
    private SAMLObjectBuilder<SubjectLocality> subjectLocalityBuilder;

    /** Builder of Endpoint objects. */
    private SAMLObjectBuilder<Endpoint> endpointBuilder;

    /** URL of the authentication manager servlet. */
    private String authenticationManagerPath;

    /**
     * Constructor.
     * 
     * @param authnManagerPath path to the authentication manager servlet
     * 
     * @throws IllegalArgumentException thrown if either the authentication manager path or encoding binding URI are
     *             null or empty
     */
    public ShibbolethSSOProfileHandler(String authnManagerPath) {
        if (DatatypeHelper.isEmpty(authnManagerPath)) {
            throw new IllegalArgumentException("Authentication manager path may not be null");
        }
        authenticationManagerPath = authnManagerPath;

        authnStatementBuilder = (SAMLObjectBuilder<AuthenticationStatement>) getBuilderFactory().getBuilder(
                AuthenticationStatement.DEFAULT_ELEMENT_NAME);

        subjectLocalityBuilder = (SAMLObjectBuilder<SubjectLocality>) getBuilderFactory().getBuilder(
                SubjectLocality.DEFAULT_ELEMENT_NAME);

        endpointBuilder = (SAMLObjectBuilder<Endpoint>) getBuilderFactory().getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return ShibbolethSSOConfiguration.PROFILE_ID;
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        log.debug("Processing incoming request");

        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        LoginContext loginContext = (LoginContext) httpRequest.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);

        if (loginContext == null) {
            log.debug("Incoming request does not contain a login context, processing as first leg of request");
            performAuthentication(inTransport, outTransport);
        } else {
            log.debug("Incoming request contains a login context, processing as second leg of request");
            completeAuthenticationRequest(inTransport, outTransport);
        }
    }

    /**
     * Creates a {@link LoginContext} an sends the request off to the AuthenticationManager to begin the process of
     * authenticating the user.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @throws ProfileException thrown if there is a problem creating the login context and transferring control to the
     *             authentication manager
     */
    protected void performAuthentication(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        HttpServletResponse httpResponse = ((HttpServletResponseAdapter) outTransport).getWrappedResponse();

        ShibbolethSSORequestContext requestContext = decodeRequest(inTransport, outTransport);
        ShibbolethSSOLoginContext loginContext = requestContext.getLoginContext();

        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(loginContext.getRelyingPartyId());
        ProfileConfiguration ssoConfig = rpConfig.getProfileConfiguration(ShibbolethSSOConfiguration.PROFILE_ID);
        if (ssoConfig == null) {
            log.error("Shibboleth SSO profile is not configured for relying party " + loginContext.getRelyingPartyId());
            throw new ProfileException("Shibboleth SSO profile is not configured for relying party "
                    + loginContext.getRelyingPartyId());
        }
        if (loginContext.getRequestedAuthenticationMethods().size() == 0
                && rpConfig.getDefaultAuthenticationMethod() != null) {
            loginContext.getRequestedAuthenticationMethods().add(rpConfig.getDefaultAuthenticationMethod());
        }

        httpRequest.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginContext);

        try {
            RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(authenticationManagerPath);
            dispatcher.forward(httpRequest, httpResponse);
            return;
        } catch (IOException ex) {
            log.error("Error forwarding Shibboleth SSO request to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding Shibboleth SSO request to AuthenticationManager", ex);
        } catch (ServletException ex) {
            log.error("Error forwarding Shibboleth SSO request to AuthenticationManager", ex);
            throw new ProfileException("Error forwarding Shibboleth SSO request to AuthenticationManager", ex);
        }
    }

    /**
     * Decodes an incoming request and populates a created request context with the resultant information.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @return the created request context
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected ShibbolethSSORequestContext decodeRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        log.debug("Decoding message with decoder binding {}", getInboundBinding());

        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();

        ShibbolethSSORequestContext requestContext = new ShibbolethSSORequestContext();
        requestContext.setCommunicationProfileId(getProfileId());

        requestContext.setMetadataProvider(getMetadataProvider());
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());

        requestContext.setCommunicationProfileId(ShibbolethSSOConfiguration.PROFILE_ID);
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(ShibbolethConstants.SHIB_SSO_PROFILE_URI);
        requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        SAMLMessageDecoder decoder = getMessageDecoders().get(getInboundBinding());
        requestContext.setMessageDecoder(decoder);
        try {
            decoder.decode(requestContext);
        } catch (MessageDecodingException e) {
            log.error("Error decoding Shibboleth SSO request", e);
            throw new ProfileException("Error decoding Shibboleth SSO request", e);
        } catch (SecurityException e) {
            log.error("Shibboleth SSO request does not meet security requirements", e);
            throw new ProfileException("Shibboleth SSO request does not meet security requirements", e);
        }

        ShibbolethSSOLoginContext loginContext = new ShibbolethSSOLoginContext();
        loginContext.setRelyingParty(requestContext.getInboundMessageIssuer());
        loginContext.setSpAssertionConsumerService(requestContext.getSpAssertionConsumerService());
        loginContext.setSpTarget(requestContext.getRelayState());
        loginContext.setAuthenticationEngineURL(authenticationManagerPath);
        loginContext.setProfileHandlerURL(HttpHelper.getRequestUriWithoutContext(httpRequest));
        requestContext.setLoginContext(loginContext);

        return requestContext;
    }

    /**
     * Creates a response to the Shibboleth SSO and sends the user, with response in tow, back to the relying party
     * after they've been authenticated.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @throws ProfileException thrown if the response can not be created and sent back to the relying party
     */
    protected void completeAuthenticationRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        ShibbolethSSOLoginContext loginContext = (ShibbolethSSOLoginContext) httpRequest
                .getAttribute(LoginContext.LOGIN_CONTEXT_KEY);

        ShibbolethSSORequestContext requestContext = buildRequestContext(loginContext, inTransport, outTransport);

        Response samlResponse;
        try {
            if (loginContext.getAuthenticationFailure() != null) {
                log.error("User authentication failed with the following error: {}", loginContext
                        .getAuthenticationFailure().toString());
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "User failed authentication"));
                throw new ProfileException("Authentication failure", loginContext.getAuthenticationFailure());
            }

            resolveAttributes(requestContext);

            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAuthenticationStatement(requestContext));
            if (requestContext.getProfileConfiguration().includeAttributeStatement()) {
                AttributeStatement attributeStatement = buildAttributeStatement(requestContext,
                        "urn:oasis:names:tc:SAML:1.0:cm:bearer");
                if (attributeStatement != null) {
                    requestContext.setReleasedAttributes(requestContext.getAttributes().keySet());
                    statements.add(attributeStatement);
                }
            }

            samlResponse = buildResponse(requestContext, statements);
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext);
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Creates an authentication request context from the current environmental information.
     * 
     * @param loginContext current login context
     * @param in inbound transport
     * @param out outbount transport
     * 
     * @return created authentication request context
     * 
     * @throws ProfileException thrown if there is a problem creating the context
     */
    protected ShibbolethSSORequestContext buildRequestContext(ShibbolethSSOLoginContext loginContext,
            HTTPInTransport in, HTTPOutTransport out) throws ProfileException {
        ShibbolethSSORequestContext requestContext = new ShibbolethSSORequestContext();
        requestContext.setCommunicationProfileId(getProfileId());

        requestContext.setMessageDecoder(getMessageDecoders().get(getInboundBinding()));

        requestContext.setLoginContext(loginContext);
        requestContext.setRelayState(loginContext.getSpTarget());

        requestContext.setInboundMessageTransport(in);
        requestContext.setInboundSAMLProtocol(ShibbolethConstants.SHIB_SSO_PROFILE_URI);

        requestContext.setOutboundMessageTransport(out);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        requestContext.setMetadataProvider(getMetadataProvider());

        String relyingPartyId = loginContext.getRelyingPartyId();
        requestContext.setPeerEntityId(relyingPartyId);
        requestContext.setInboundMessageIssuer(relyingPartyId);

        populateRequestContext(requestContext);

        return requestContext;
    }

    /** {@inheritDoc} */
    protected void populateRelyingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateRelyingPartyInformation(requestContext);

        EntityDescriptor relyingPartyMetadata = requestContext.getPeerEntityMetadata();
        if (relyingPartyMetadata != null) {
            requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setPeerEntityRoleMetadata(relyingPartyMetadata.getSPSSODescriptor(SAMLConstants.SAML11P_NS));
        }
    }

    /** {@inheritDoc} */
    protected void populateAssertingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateAssertingPartyInformation(requestContext);

        EntityDescriptor localEntityDescriptor = requestContext.getLocalEntityMetadata();
        if (localEntityDescriptor != null) {
            requestContext.setLocalEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setLocalEntityRoleMetadata(localEntityDescriptor
                    .getIDPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    /** {@inheritDoc} */
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        // nothing to do here
    }

    /**
     * Selects the appropriate endpoint for the relying party and stores it in the request context.
     * 
     * @param requestContext current request context
     * 
     * @return Endpoint selected from the information provided in the request context
     */
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) {
        ShibbolethSSOLoginContext loginContext = ((ShibbolethSSORequestContext) requestContext).getLoginContext();

        Endpoint endpoint = null;
        if (requestContext.getRelyingPartyConfiguration().getRelyingPartyId() == SAMLMDRelyingPartyConfigurationManager.ANONYMOUS_RP_NAME) {
            if (loginContext.getSpAssertionConsumerService() != null) {
                endpoint = endpointBuilder.buildObject();
                endpoint.setLocation(loginContext.getSpAssertionConsumerService());
                endpoint.setBinding(getSupportedOutboundBindings().get(0));
                log.warn("Generating endpoint for anonymous relying party. ACS url {} and binding {}", new Object[] {
                        requestContext.getInboundMessageIssuer(), endpoint.getLocation(), endpoint.getBinding(), });
            }else{
               log.warn("Unable to generate endpoint for anonymous party.  No ACS url provided."); 
            }
        } else {
            ShibbolethSSOEndpointSelector endpointSelector = new ShibbolethSSOEndpointSelector();
            endpointSelector.setSpAssertionConsumerService(loginContext.getSpAssertionConsumerService());
            endpointSelector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
            endpointSelector.setMetadataProvider(getMetadataProvider());
            endpointSelector.setEntityMetadata(requestContext.getPeerEntityMetadata());
            endpointSelector.setEntityRoleMetadata(requestContext.getPeerEntityRoleMetadata());
            endpointSelector.setSamlRequest(requestContext.getInboundSAMLMessage());
            endpointSelector.getSupportedIssuerBindings().addAll(getSupportedOutboundBindings());
            endpoint = endpointSelector.selectEndpoint();
        }

        return endpoint;
    }

    /**
     * Builds the authentication statement for the authenticated principal.
     * 
     * @param requestContext current request context
     * 
     * @return the created statement
     * 
     * @throws ProfileException thrown if the authentication statement can not be created
     */
    protected AuthenticationStatement buildAuthenticationStatement(ShibbolethSSORequestContext requestContext)
            throws ProfileException {
        ShibbolethSSOLoginContext loginContext = requestContext.getLoginContext();

        AuthenticationStatement statement = authnStatementBuilder.buildObject();
        statement.setAuthenticationInstant(loginContext.getAuthenticationInstant());
        statement.setAuthenticationMethod(loginContext.getAuthenticationMethod());

        statement.setSubjectLocality(buildSubjectLocality(requestContext));

        Subject statementSubject = buildSubject(requestContext, "urn:oasis:names:tc:SAML:1.0:cm:bearer");
        statement.setSubject(statementSubject);

        return statement;
    }

    /**
     * Constructs the subject locality for the authentication statement.
     * 
     * @param requestContext curent request context
     * 
     * @return subject locality for the authentication statement
     */
    protected SubjectLocality buildSubjectLocality(ShibbolethSSORequestContext requestContext) {
        SubjectLocality subjectLocality = subjectLocalityBuilder.buildObject();

        HTTPInTransport inTransport = (HTTPInTransport) requestContext.getInboundMessageTransport();
        subjectLocality.setIPAddress(inTransport.getPeerAddress());

        return subjectLocality;
    }

    /** Represents the internal state of a Shibboleth SSO Request while it's being processed by the IdP. */
    public class ShibbolethSSORequestContext extends
            BaseSAML1ProfileRequestContext<Request, Response, ShibbolethSSOConfiguration> {

        /** SP-provide assertion consumer service URL. */
        private String spAssertionConsumerService;

        /** Current login context. */
        private ShibbolethSSOLoginContext loginContext;

        /**
         * Gets the current login context.
         * 
         * @return current login context
         */
        public ShibbolethSSOLoginContext getLoginContext() {
            return loginContext;
        }

        /**
         * Sets the current login context.
         * 
         * @param context current login context
         */
        public void setLoginContext(ShibbolethSSOLoginContext context) {
            loginContext = context;
        }

        /**
         * Gets the SP-provided assertion consumer service URL.
         * 
         * @return SP-provided assertion consumer service URL
         */
        public String getSpAssertionConsumerService() {
            return spAssertionConsumerService;
        }

        /**
         * Sets the SP-provided assertion consumer service URL.
         * 
         * @param acs SP-provided assertion consumer service URL
         */
        public void setSpAssertionConsumerService(String acs) {
            spAssertionConsumerService = acs;
        }
    }
}