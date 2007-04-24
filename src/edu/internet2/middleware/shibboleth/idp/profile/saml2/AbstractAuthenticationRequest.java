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

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.ArtifactMap;
import org.opensaml.common.binding.SAMLArtifactFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Condition;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.GetComplete;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.saml2.SSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;

/**
 * Abstract SAML 2.0 Authentication Request profile handler.
 */
public abstract class AbstractAuthenticationRequest extends
		AbstractSAML2ProfileHandler {

	/** Class logger. */
	private static final Logger log = Logger
			.getLogger(AbstractAuthenticationRequest.class.getName());

	/** Key in an HttpSession for the AssertionConsumerService object. */
	protected static final String ACS_SESSION_KEY = "AssertionConsumerService";

	/** Key in an HttpSession for the RelyingParty. */
	protected static final String RPCONFIG_SESSION_KEY = "RelyingPartyConfiguration";

	/** Key in an HttpSession for the SSOConfiguration. */
	protected static final String SSOCONFIG_SESSION_KEY = "SSOConfiguration";

	/** Key in an HttpSession for the SPSSODescriptor. */
	protected static final String SPSSODESC_SESSION_KEY = "SPSSODescriptor";

	/** Key in an HttpSession for the AuthnRequest. */
	protected static final String AUTHNREQUEST_SESSION_KEY = "AuthnRequest";

	/** Key in an HttpSession for the Issuer. */
	protected static final String ISSUER_SESSION_KEY = "Issuer";

	/**
	 * Backing store for artifacts. This must be shared between ShibbolethSSO
	 * and AttributeQuery.
	 */
	protected ArtifactMap artifactMap;

	/** The path to the IdP's AuthenticationManager servlet */
	protected String authnMgrURL;

	/** AuthenticationManager to be used */
	protected AuthenticationManager authnMgr;

	/** ArtifactFactory used to make artifacts. */
	protected SAMLArtifactFactory artifactFactory;

	/** A pool of XML parsers. */
	protected ParserPool parserPool;

	/**
	 * Constructor.
	 */
	public AbstractAuthenticationRequest() {

		parserPool = new BasicParserPool();
		artifactFactory = new SAMLArtifactFactory();
	}

	/**
	 * Set the Authentication Mananger.
	 * 
	 * @param authnManager
	 *            The IdP's AuthenticationManager.
	 */
	public void setAuthenticationManager(AuthenticationManager authnManager) {
		this.authnMgr = authnMgr;
	}

	/**
	 * Set the ArtifactMap.
	 * 
	 * @param artifactMap
	 *            The IdP's ArtifactMap.
	 */
	public void setArtifactMap(ArtifactMap artifactMap) {
		this.artifactMap = artifactMap;
	}

	/**
	 * Evaluate a SAML 2 AuthenticationRequest message.
	 * 
	 * @param authnRequest
	 *            A SAML 2 AuthenticationRequest
	 * @param issuer
	 *            The issuer of the authnRequest.
	 * @param session
	 *            The HttpSession of the request.
	 * @param relyingParty
	 *            The RelyingPartyConfiguration for the request.
	 * @param ssoConfig
	 *            The SSOConfiguration for the request.
	 * @param spDescriptor
	 *            The SPSSODescriptor for the request.
	 * 
	 * @return A Response containing a failure message or a AuthenticationStmt.
	 * 
	 * @throws ServletException
	 *             On Error.
	 */
	protected Response evaluateRequest(final AuthnRequest authnRequest,
			final Issuer issuer, final HttpSession session,
			final RelyingPartyConfiguration relyingParty,
			final SSOConfiguration ssoConfig, final SPSSODescriptor spDescriptor)
			throws ServletException {

		Response samlResponse;

		try {
			// check if the authentication was successful.
			Saml2LoginContext loginCtx = getLoginContext(session);
			if (!loginCtx.getAuthenticationOK()) {
				// if authentication failed, send the appropriate SAML error
				// message.
				String failureMessage = loginCtx
						.getAuthenticationFailureMessage();
				Status failureStatus = buildStatus(StatusCode.RESPONDER_URI,
						StatusCode.AUTHN_FAILED_URI, failureMessage);
				samlResponse = buildResponse(authnRequest.getID(),
						new DateTime(), relyingParty.getProviderId(),
						failureStatus);

				return samlResponse;
			}

			// the user successfully authenticated.
			// build an authentication assertion.
			samlResponse = buildResponse(authnRequest.getID(), new DateTime(),
					relyingParty.getProviderId(), buildStatus(
							StatusCode.SUCCESS_URI, null, null));

			DateTime now = new DateTime();
			Conditions conditions = conditionsBuilder.buildObject();
			conditions.setNotBefore(now.minusSeconds(30)); // for now, clock
															// skew is
															// hard-coded to 30
															// seconds.
			conditions.setNotOnOrAfter(now.plus(ssoConfig
					.getAssertionLifetime()));

			// XXX: don't blindly copy conditions from the AuthnRequest.
			List<Condition> requestConditions = authnRequest.getConditions()
					.getConditions();
			if (requestConditions != null && requestConditions.size() > 0) {
				conditions.getConditions().addAll(requestConditions);
			}

			Assertion assertion = buildAssertion(authnRequest.getSubject(),
					conditions, issuer, new String[] { relyingParty
							.getRelyingPartyId() });
			setAuthenticationStatement(assertion, loginCtx, authnRequest);

			samlResponse.getAssertions().add(assertion);

			// retrieve the AssertionConsumerService endpoint (we parsed it in
			// verifyAuthnRequest()
			AssertionConsumerService acsEndpoint = getACSEndpointFromSession(session);

		} catch (AuthenticationRequestException ex) {

			Status errorStatus = ex.getStatus();
			if (errorStatus == null) {
				// if no explicit status code was set,
				// assume the error was in the message.
				samlResponse = buildResponse(authnRequest.getID(),
						new DateTime(), relyingParty.getProviderId(),
						errorStatus);
			}
		}

		return samlResponse;
	}

	/**
	 * Check that a request's issuer can be found in the metadata. If so, store
	 * the relevant metadata objects in the user's session.
	 * 
	 * @param issuer
	 *            The issuer of the AuthnRequest.
	 * @param relyingParty
	 *            The RelyingPartyConfiguration for the issuer.
	 * @param ssoConfig
	 *            The SSOConfiguration for the relyingParty
	 * @param spDescriptor
	 *            The SPSSODescriptor for the ssoConfig.
	 * 
	 * @return <code>true</code> if Metadata was found for the issuer;
	 *         otherwise, <code>false</code>.
	 */
	protected boolean findMetadataForSSORequest(Issuer issuer,
			RelyingPartyConfiguration relyingParty, SSOConfiguration ssoConfig,
			SPSSODescriptor spDescriptor) {

		MetadataProvider metadataProvider = getRelyingPartyConfigurationManager()
				.getMetadataProvider();
		String providerId = issuer.getSPProvidedID();
		relyingParty = getRelyingPartyConfigurationManager()
				.getRelyingPartyConfiguration(providerId);
		ssoConfig = (SSOConfiguration) relyingParty.getProfileConfigurations()
				.get(SSOConfiguration.PROFILE_ID);

		try {
			spDescriptor = metadataProvider.getEntityDescriptor(
					relyingParty.getRelyingPartyId()).getSPSSODescriptor(
					SAML20_PROTOCOL_URI);
		} catch (MetadataProviderException ex) {
			log.error(
					"SAML 2 Authentication Request: Unable to locate metadata for SP "
							+ providerId + " for protocol "
							+ SAML20_PROTOCOL_URI, ex);
			return false;
		}

		if (spDescriptor == null) {
			log
					.error("SAML 2 Authentication Request: Unable to locate metadata for SP "
							+ providerId
							+ " for protocol "
							+ SAML20_PROTOCOL_URI);
			return false;
		}

		return true;
	}

	/**
	 * Check if the user has already been authenticated.
	 * 
	 * @param httpSession
	 *            the user's HttpSession.
	 * 
	 * @return <code>true</code> if the user has been authenticated. otherwise
	 *         <code>false</code>
	 */
	protected boolean hasUserAuthenticated(final HttpSession httpSession) {

		// if the user has authenticated, their session will have a LoginContext

		Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
		return (o != null && o instanceof LoginContext);
	}

	/**
	 * Store a user's AuthnRequest and Issuer in the session.
	 * 
	 * @param authnRequest
	 *            A SAML 2 AuthnRequest.
	 * @param issuer
	 *            The issuer of the AuthnRequest.
	 * @param session
	 *            The HttpSession in which the data should be stored.
	 * @param relyingParty
	 *            The RelyingPartyConfiguration for the issuer.
	 * @param ssoConfig
	 *            The SSOConfiguration for the relyingParty
	 * @param spDescriptor
	 *            The SPSSODescriptor for the ssoConfig.
	 */
	protected void storeRequestData(final HttpSession session,
			final AuthnRequest authnRequest, final Issuer issuer,
			final RelyingPartyConfiguration relyingParty,
			final SSOConfiguration ssoConfig, final SPSSODescriptor spDescriptor) {

		if (session == null) {
			return;
		}

		session.setAttribute(AUTHNREQUEST_SESSION_KEY, authnRequest);
		session.setAttribute(ISSUER_SESSION_KEY, issuer);
		session.setAttribute(RPCONFIG_SESSION_KEY, relyingParty);
		session.setAttribute(SSOCONFIG_SESSION_KEY, ssoConfig);
		session.setAttribute(SPSSODESC_SESSION_KEY, spDescriptor);
	}

	/**
	 * Retrieve the AuthnRequest and Issuer from a session.
	 * 
	 * @param session
	 *            The HttpSession in which the data was stored.
	 * @param authnRequest
	 *            Will be populated with the AuthnRequest.
	 * @param issuer
	 *            Will be populated with the ssuer of the AuthnRequest.
	 * @param relyingParty
	 *            Will be populated with the RelyingPartyConfiguration for the
	 *            issuer.
	 * @param ssoConfig
	 *            Will be populated with the SSOConfiguration for the
	 *            relyingParty
	 * @param spDescriptor
	 *            Will be populated with the SPSSODescriptor for the ssoConfig.
	 */
	protected void retrieveRequestData(final HttpSession session,
			AuthnRequest authnRequest, Issuer issuer,
			RelyingPartyConfiguration relyingParty, SSOConfiguration ssoConfig,
			SPSSODescriptor spDescriptor) {

		if (session == null) {
			authnRequest = null;
			issuer = null;
		}

		authnRequest = (AuthnRequest) session
				.getAttribute(AUTHNREQUEST_SESSION_KEY);
		issuer = (Issuer) session.getAttribute(ISSUER_SESSION_KEY);
		relyingParty = (RelyingPartyConfiguration) session
				.getAttribute(RPCONFIG_SESSION_KEY);
		ssoConfig = (SSOConfiguration) session
				.getAttribute(SSOCONFIG_SESSION_KEY);
		spDescriptor = (SPSSODescriptor) session
				.getAttribute(SPSSODESC_SESSION_KEY);

		session.removeAttribute(AUTHNREQUEST_SESSION_KEY);
		session.removeAttribute(ISSUER_SESSION_KEY);
		session.removeAttribute(RPCONFIG_SESSION_KEY);
		session.removeAttribute(SSOCONFIG_SESSION_KEY);
		session.removeAttribute(SPSSODESC_SESSION_KEY);
	}

	/**
	 * Check if the user has already been authenticated. If so, return the
	 * LoginContext. If not, redirect the user to the AuthenticationManager.
	 * 
	 * @param authnRequest
	 *            The SAML 2 AuthnRequest.
	 * @param httpSession
	 *            The user's HttpSession.
	 * @param request
	 *            The user's HttpServletRequest.
	 * @param response
	 *            The user's HttpServletResponse.
	 * 
	 * @return A LoginContext for the authenticated user.
	 * 
	 * @throws SerlvetException
	 *             on error.
	 */
	protected void authenticateUser(final AuthnRequest authnRequest,
			final HttpSession httpSession, final HttpServletRequest request,
			final HttpServletResponse response) throws ServletException {

		// Forward the request to the AuthenticationManager.
		// When the AuthenticationManager is done it will
		// forward the request back to this servlet.

		Saml2LoginContext loginCtx = new Saml2LoginContext(authnRequest);
		loginCtx.setProfileHandlerURL(request.getPathInfo());
		httpSession.setAttribute(LoginContext.LOGIN_CONTEXT_KEY, loginCtx);
		try {
			RequestDispatcher dispatcher = request
					.getRequestDispatcher(authnMgrURL);
			dispatcher.forward(request, response);
		} catch (IOException ex) {
			log.error("Error forwarding SAML 2 AuthnRequest "
					+ authnRequest.getID() + " to AuthenticationManager", ex);
			throw new ServletException("Error forwarding SAML 2 AuthnRequest "
					+ authnRequest.getID() + " to AuthenticationManager", ex);
		}
	}

	/**
	 * Build an AuthnStatement and add it to a Response.
	 * 
	 * @param response
	 *            The Response to which the AuthnStatement will be added.
	 * @param loginCtx
	 *            The LoginContext of the sucessfully authenticated user.
	 * @param authnRequest
	 *            The AuthnRequest that prompted this message.
	 * @param ssoConfig
	 *            The SSOConfiguration for the RP to which we are addressing
	 *            this message.
	 * @param issuer
	 *            The IdP's identifier.
	 * @param audiences
	 *            An array of URIs restricting the audience of this assertion.
	 */
	protected void setAuthenticationStatement(Assertion assertion,
			final Saml2LoginContext loginContext,
			final AuthnRequest authnRequest) throws ServletException {

		// Build the AuthnCtx. We need to determine if the user was
		// authenticated
		// with an AuthnContextClassRef or a AuthnContextDeclRef
		AuthnContext authnCtx = buildAuthnCtx(authnRequest
				.getRequestedAuthnContext(), loginContext);
		if (authnCtx == null) {
			log.error("Error respond to SAML 2 AuthnRequest "
					+ authnRequest.getID()
					+ " : Unable to determine authentication method");
		}

		AuthnStatement stmt = authnStatementBuilder.buildObject();
		stmt.setAuthnInstant(loginContext.getAuthenticationInstant());
		stmt.setAuthnContext(authnCtx);

		// add the AuthnStatement to the Assertion
		List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
		authnStatements.add(stmt);
	}

	/**
	 * Create the AuthnContex object.
	 * 
	 * To do this, we have to walk the AuthnRequest's RequestedAuthnContext
	 * object and compare any values we find to what's set in the loginContext.
	 * 
	 * @param requestedAuthnCtx
	 *            The RequestedAuthnContext from the Authentication Request.
	 * @param authnMethod
	 *            The authentication method that was used.
	 * 
	 * @return An AuthnCtx object on success or <code>null</code> on failure.
	 */
	protected AuthnContext buildAuthnCtx(
			final RequestedAuthnContext requestedAuthnCtx,
			final Saml2LoginContext loginContext) {

		// this method assumes that only one URI will match.

		AuthnContext authnCtx = authnContextBuilder.buildObject();
		String authnMethod = loginContext.getAuthenticationMethod();

		List<AuthnContextClassRef> authnClasses = requestedAuthnCtx
				.getAuthnContextClassRefs();
		List<AuthnContextDeclRef> authnDeclRefs = requestedAuthnCtx
				.getAuthnContextDeclRefs();

		if (authnClasses != null) {
			for (AuthnContextClassRef classRef : authnClasses) {
				if (classRef != null) {
					String s = classRef.getAuthnContextClassRef();
					if (s != null && authnMethod.equals(s)) {
						AuthnContextClassRef ref = authnContextClassRefBuilder
								.buildObject();
						authnCtx.setAuthnContextClassRef(ref);
						return authnCtx;
					}
				}
			}
		}

		// if no AuthnContextClassRef's matched, try the DeclRefs
		if (authnDeclRefs != null) {
			for (AuthnContextDeclRef declRef : authnDeclRefs) {
				if (declRef != null) {
					String s = declRef.getAuthnContextDeclRef();
					if (s != null && authnMethod.equals((s))) {
						AuthnContextDeclRef ref = authnContextDeclRefBuilder
								.buildObject();
						authnCtx.setAuthnContextDeclRef(ref);
						return authnCtx;
					}
				}
			}
		}

		// no matches were found.
		return null;
	}

	/**
	 * Get the user's LoginContext.
	 * 
	 * @param httpSession
	 *            The user's HttpSession.
	 * 
	 * @return The user's LoginContext.
	 * 
	 * @throws ServletException
	 *             On error.
	 */
	protected Saml2LoginContext getLoginContext(final HttpSession httpSession)
			throws ServletException {

		Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
		if (o == null) {
			log.error("User's session does not contain a LoginContext object.");
			throw new ServletException(
					"User's session does not contain a LoginContext object.");
		}

		if (!(o instanceof Saml2LoginContext)) {
			log
					.error("Invalid login context object -- object is not an instance of Saml2LoginContext.");
			throw new ServletException("Invalid login context object.");
		}

		Saml2LoginContext ctx = (Saml2LoginContext) o;

		httpSession.removeAttribute(LoginContext.LOGIN_CONTEXT_KEY);

		return ctx;
	}

	/**
	 * Verify the AuthnRequest is well-formed.
	 * 
	 * @param authnRequest
	 *            The user's SAML 2 AuthnRequest.
	 * @param issuer
	 *            The Issuer of the AuthnRequest.
	 * @param relyingParty
	 *            The relying party configuration for the request's originator.
	 * @param session
	 *            The user's HttpSession.
	 * 
	 * @throws AuthenticationRequestException
	 *             on error.
	 */
	protected void verifyAuthnRequest(final AuthnRequest authnRequest,
			Issuer issuer, final RelyingPartyConfiguration relyingParty,
			final HttpSession session) throws AuthenticationRequestException {

		Status failureStatus;

		// Check if we are in scope to handle this AuthnRequest
		checkScope(authnRequest, issuer.getSPProvidedID());

		// XXX: run signature checks on authnRequest

		// verify that the AssertionConsumerService url is valid.
		AssertionConsumerService acsEndpoint = getAndVerifyACSEndpoint(
				authnRequest, relyingParty.getRelyingPartyId(),
				getRelyingPartyConfigurationManager().getMetadataProvider());
		session.setAttribute(ACS_SESSION_KEY, acsEndpoint);

		// check for nameID constraints.
		Subject subject = getAndVerifySubject(authnRequest);
	}

	/**
	 * Get and verify the Subject element.
	 * 
	 * @param authnRequest
	 *            The SAML 2 AuthnRequest.
	 * 
	 * @return A Subject element.
	 * 
	 * @throws AuthenticationRequestException
	 *             on error.
	 */
	protected Subject getAndVerifySubject(final AuthnRequest authnRequest)
			throws AuthenticationRequestException {

		Status failureStatus;

		Subject subject = authnRequest.getSubject();

		if (subject == null) {
			failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
					"SAML 2 AuthnRequest " + authnRequest.getID()
							+ " is malformed: It does not contain a Subject.");
			throw new AuthenticationRequestException(
					"AuthnRequest lacks a Subject", failureStatus);
		}

		// The Web Browser SSO profile disallows SubjectConfirmation
		// methods in the requested subject.
		List<SubjectConfirmation> confMethods = subject
				.getSubjectConfirmations();
		if (confMethods != null || confMethods.size() > 0) {
			log
					.error("SAML 2 AuthnRequest "
							+ authnRequest.getID()
							+ " is malformed: It contains SubjectConfirmation elements.");
			failureStatus = buildStatus(
					StatusCode.REQUESTER_URI,
					null,
					"SAML 2 AuthnRequest "
							+ authnRequest.getID()
							+ " is malformed: It contains SubjectConfirmation elements.");
			throw new AuthenticationRequestException(
					"AuthnRequest contains SubjectConfirmation elements",
					failureStatus);
		}

		return subject;
	}

	/**
	 * Return the endpoint URL and protocol binding to use for the AuthnRequest.
	 * 
	 * @param authnRequest
	 *            The SAML 2 AuthnRequest.
	 * @param providerId
	 *            The SP's providerId.
	 * @param metadata
	 *            The appropriate Metadata.
	 * 
	 * @return The AssertionConsumerService for the endpoint, or
	 *         <code>null</code> on error.
	 * 
	 * @throws AuthenticationRequestException
	 *             On error.
	 */
	protected AssertionConsumerService getAndVerifyACSEndpoint(
			final AuthnRequest authnRequest, String providerId,
			final MetadataProvider metadata)
			throws AuthenticationRequestException {

		Status failureStatus;

		// Either the AssertionConsumerServiceIndex must be present
		// or AssertionConsumerServiceURL must be present.

		Integer idx = authnRequest.getAssertionConsumerServiceIndex();
		String acsURL = authnRequest.getAssertionConsumerServiceURL();

		if (idx != null && acsURL != null) {
			log
					.error("SAML 2 AuthnRequest "
							+ authnRequest.getID()
							+ " is malformed: It contains both an AssertionConsumerServiceIndex and an AssertionConsumerServiceURL");
			failureStatus = buildStatus(
					StatusCode.REQUESTER_URI,
					null,
					"SAML 2 AuthnRequest "
							+ authnRequest.getID()
							+ " is malformed: It contains both an AssertionConsumerServiceIndex and an AssertionConsumerServiceURL");
			throw new AuthenticationRequestException("Malformed AuthnRequest",
					failureStatus);
		}

		SPSSODescriptor spDescriptor;
		try {
			spDescriptor = metadata.getEntityDescriptor(providerId)
					.getSPSSODescriptor(SAML20_PROTOCOL_URI);
		} catch (MetadataProviderException ex) {
			log.error(
					"Unable retrieve SPSSODescriptor metadata for providerId "
							+ providerId
							+ " while processing SAML 2 AuthnRequest "
							+ authnRequest.getID(), ex);
			failureStatus = buildStatus(StatusCode.RESPONDER_URI, null,
					"Unable to locate metadata for " + providerId);
			throw new AuthenticationRequestException(
					"Unable to locate metadata", ex, failureStatus);
		}

		List<AssertionConsumerService> acsList = spDescriptor
				.getAssertionConsumerServices();

		// if the ACS index is specified, retrieve it from the metadata
		if (idx != null) {

			int i = idx.intValue();

			// if the index is out of range, return an appropriate error.
			if (i > acsList.size()) {
				log.error("Illegal AssertionConsumerIndex specicifed (" + i
						+ ") in SAML 2 AuthnRequest " + authnRequest.getID());

				failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
						"Illegal AssertionConsumerIndex specicifed (" + i
								+ ") in SAML 2 AuthnRequest "
								+ authnRequest.getID());

				throw new AuthenticationRequestException(
						"Illegal AssertionConsumerIndex in AuthnRequest",
						failureStatus);
			}

			return acsList.get(i);
		}

		// if the ACS endpoint is specified, validate it against the metadata
		String protocolBinding = authnRequest.getProtocolBinding();
		for (AssertionConsumerService acs : acsList) {
			if (acsURL.equals(acs.getLocation())) {
				if (protocolBinding != null) {
					if (protocolBinding.equals(acs.getBinding())) {
						return acs;
					}
				}
			}
		}

		log
				.error("Error processing SAML 2 AuthnRequest message "
						+ authnRequest.getID()
						+ ": Unable to validate AssertionConsumerServiceURL against metadata: "
						+ acsURL + " for binding " + protocolBinding);

		failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
				"Unable to validate AssertionConsumerService against metadata.");

		throw new AuthenticationRequestException(
				"SAML 2 AuthenticationRequest: Unable to validate AssertionConsumerService against Metadata",
				failureStatus);
	}

	/**
	 * Retrieve a parsed AssertionConsumerService endpoint from the user's
	 * session.
	 * 
	 * @param session
	 *            The user's HttpSession.
	 * 
	 * @return An AssertionConsumerServiceEndpoint object.
	 * 
	 * @throws ServletException
	 *             On error.
	 */
	protected AssertionConsumerService getACSEndpointFromSession(
			final HttpSession session) throws ServletException {

		Object o = session.getAttribute(ACS_SESSION_KEY);
		if (o == null) {
			log
					.error("User's session does not contain an AssertionConsumerService object.");
			throw new ServletException(
					"User's session does not contain an AssertionConsumerService object.");
		}

		if (!(o instanceof AssertionConsumerService)) {
			log
					.error("Invalid session data -- object is not an instance of AssertionConsumerService.");
			throw new ServletException(
					"Invalid session data -- object is not an instance of AssertionConsumerService.");
		}

		AssertionConsumerService endpoint = (AssertionConsumerService) o;

		session.removeAttribute(ACS_SESSION_KEY);

		return endpoint;
	}

	/**
	 * Check if an {@link AuthnRequest} contains a {@link Scoping} element. If
	 * so, check if the specified IdP is in the {@link IDPList} element. If no
	 * Scoping element is present, this method returns <code>true</code>.
	 * 
	 * @param authnRequest
	 *            The {@link AuthnRequest} element to check.
	 * @param providerId
	 *            The IdP's ProviderID.
	 * 
	 * @throws AuthenticationRequestException
	 *             on error.
	 */
	protected void checkScope(final AuthnRequest authnRequest, String providerId)
			throws AuthenticationRequestException {

		Status failureStatus;

		List<String> idpEntries = new LinkedList<String>();

		Scoping scoping = authnRequest.getScoping();
		if (scoping == null) {
			return;
		}

		// process all of the explicitly listed idp provider ids
		IDPList idpList = scoping.getIDPList();
		if (idpList == null) {
			return;
		}

		List<IDPEntry> explicitIDPEntries = idpList.getIDPEntrys();
		if (explicitIDPEntries != null) {
			for (IDPEntry entry : explicitIDPEntries) {
				String s = entry.getProviderID();
				if (s != null) {
					idpEntries.add(s);
				}
			}
		}

		// If the IDPList is incomplete, retrieve the complete list
		// and add the entries to idpEntries.
		GetComplete getComplete = idpList.getGetComplete();
		IDPList referencedIdPs = getCompleteIDPList(getComplete);
		if (referencedIdPs != null) {
			List<IDPEntry> referencedIDPEntries = referencedIdPs.getIDPEntrys();
			if (referencedIDPEntries != null) {
				for (IDPEntry entry : referencedIDPEntries) {
					String s = entry.getProviderID();
					if (s != null) {
						idpEntries.add(s);
					}
				}
			}
		}

		// iterate over all the IDPEntries we've gathered,
		// and check if we're in scope.
		for (String requestProviderId : idpEntries) {
			if (providerId.equals(requestProviderId)) {
				log.debug("Found Scoping match for IdP: (" + providerId + ")");
				return;
			}
		}

		log.error("SAML 2 AuthnRequest " + authnRequest.getID()
				+ " contains a Scoping element which "
				+ "does not contain a providerID registered with this IdP.");

		failureStatus = buildStatus(StatusCode.RESPONDER_URI,
				StatusCode.NO_SUPPORTED_IDP_URI, null);
		throw new AuthenticationRequestException(
				"Unrecognized providerID in Scoping element", failureStatus);
	}

	/**
	 * Retrieve an incomplete IDPlist.
	 * 
	 * This only handles URL-based <GetComplete/> references.
	 * 
	 * @param getComplete
	 *            The (possibly <code>null</code>) &lt;GetComplete/&gt;
	 *            element
	 * 
	 * @return an {@link IDPList} or <code>null</code> if the uri can't be
	 *         dereferenced.
	 */
	protected IDPList getCompleteIDPList(final GetComplete getComplete) {

		// XXX: enhance this method to cache the url and last-modified-header

		if (getComplete == null) {
			return null;
		}

		String uri = getComplete.getGetComplete();
		if (uri != null) {
			return null;
		}

		IDPList idpList = null;
		InputStream istream = null;

		try {
			URL url = new URL(uri);
			URLConnection conn = url.openConnection();
			istream = conn.getInputStream();

			// convert the raw data into an XML object
			Document doc = parserPool.parse(istream);
			Element docElement = doc.getDocumentElement();
			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory()
					.getUnmarshaller(docElement);
			idpList = (IDPList) unmarshaller.unmarshall(docElement);

		} catch (MalformedURLException ex) {
			log.error(
					"Unable to retrieve GetComplete IDPList. Unsupported URI: "
							+ uri, ex);
		} catch (IOException ex) {
			log.error("IO Error while retreieving GetComplete IDPList from "
					+ uri, ex);
		} catch (ConfigurationException ex) {
			log.error(
					"Internal OpenSAML error while parsing GetComplete IDPList from "
							+ uri, ex);
		} catch (XMLParserException ex) {
			log.error(
					"Internal OpenSAML error while parsing GetComplete IDPList from "
							+ uri, ex);
		} catch (UnmarshallingException ex) {
			log.error(
					"Internal OpenSAML error while unmarshalling GetComplete IDPList from "
							+ uri, ex);
		} finally {

			if (istream != null) {
				try {
					istream.close();
				} catch (IOException ex) {
					// pass
				}
			}
		}

		return idpList;
	}
}