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

import java.io.InputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.saml2.SSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.GetComplete;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.MetadataProvider;
import org.opensaml.saml2.metadata.provider.ProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.parse.XMLParserException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.xml.sax.InputSource;

/**
 * SAML 2.0 Authentication Request profile handler
 */
public class AuthenticationRequest extends AbstractProfileHandler {

	private static final Logger log = Logger
			.getLogger(AuthenticationRequest.class.getName());

	/** SAML 2.0 protocol URI. */
	public static final String SAML20_PROTOCOL_URI = "urn:oasis:names:tc:SAML:2.0:protocol";

	/** The RelyingPartyManager. */
	protected RelyingPartyManager rpManager;

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

	/** Builder for Assertion elements. */
	protected XMLObjectBuilder assertionBuilder;

	/** Builder for AuthnStatement elements. */
	protected XMLObjectBuilder authnStatementBuilder;

	/** Builder for AuthnContext elements. */
	protected XMLObjectBuilder authnContextBuilder;

	/** Builder for AuthnContextClassRef elements. */
	protected XMLObjectBuilder authnContextClassRefBuilder;

	/** Builder for AuthnContextDeclRef elements. */
	protected XMLObjectBuilder authnContextDeclRefBuilder;

	/** Builder for AudienceRestriction conditions. */
	protected XMLObjectBuilder audienceRestrictionBuilder;

	/** Builder for Audience elemenets. */
	protected XMLObjectBuilder audienceBuilder;

	/**
	 * Constructor.
	 */
	public AuthenticationRequest() {

		parserPool = new ParserPool();
		artifactFactory = new SAMLArtifactFactory();

		assertionBuilder = getBuilderFactory().getBuilder(
				Assertion.DEFAULT_ELEMENT_NAME);
		authnStatementBuilder = getBuilderFactory().getBuilder(
				AuthnStatment.DEFULT_ELEMENT_NAME);
		authnContextBuilder = getBuilderFactory().getBuilder(
				AuthnContext.DEFAULT_ELEMENT_NAME);
		authnContextClassRefBuilder = getBuilderFactory().getBuilder(
				AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		authnContextDeclRefBuilder = getBuilderFactory().getBuilder(
				AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
		audienceRestrictionBuilder = getBuilderFactory().getBuilder(
				AudienceRestriction.DEFAULT_ELEMENT_NAME);
		audienceBuilder = getBuilderFactory().getBuilder(
				Audience.DEFAULT_ELEMENT_NAME);
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
	 * Set the RelyingPartyManager.
	 * 
	 * @param rpManager
	 *            The IdP's RelyingParyManager.
	 */
	public void setRelyingPartyManager(RelyingPartyManager rpManager) {
		this.rpManager = rpManager;
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

	/** {@inheritDoc} */
	public boolean processRequest(ServletRequest request,
			ServletResponse response) throws ServletException {

		// Only http servlets are supported for now.
		if (!(request instanceof HttpServletRequest)) {
			log.error("Received a non-HTTP request from "
					+ request.getRemoteHost());
			throw new ServletException("Received a non-HTTP request");
		}

		HttpServletRequest httpReq = (HttpServletRequest) request;
		HttpServletResponse httpResp = (HttpServletResponse) response;
		HttpSession httpSession = httpReq.getSession();

		AuthnRequest authnRequest;
		try {
			authnRequest = decodeMessage(request); // this will need to change
			// to accomodate the factory
		} catch (BindingException ex) {
			log.error("Unable to decode SAML 2 authentication request", ex);
			throw new ServletException(
					"Error decoding SAML 2 authentication request", ex);
		}

		Issuer issuer = authnRequest.getIssuer();
		String providerId = authnRequest.getIssuer().getSPProvidedID();
		RelyingPartyConfiguration relyingParty = rpManager
				.getRelyingPartyConfiguration(providerId);
		SSOConfiguration ssoConfig = relyingParty.getProfileConfigurations()
				.get(SSOConfiguration.PROFILE_ID);
		SPSSODescriptor spDescriptor;

		try {

			// If the user hasn't been authenticated, validate the AuthnRequest
			// and
			// redirect to AuthenticationManager to authenticate them.
			// Otherwise, the user has been authenticated, so generate an
			// AuthenticationStatement.
			if (!hasUserAuthenticated()) {
				verifyAuthnRequest(authnRequest);
				authenticateUser(authnRequest, httpSession, httpReq, httpResp);
			}

			// the user has been authenticated.
			// check if the authentication was successful.

			Saml2LoginContext loginCtx = getLoginContext(httpSession);
			if (!loginCtx.getAuthenticationOK()) {
				// if authentication failed, send the appropriate SAML error
				// message.
				String failureMessage = loginCtx
						.getAuthenticationFailureMessage();
				Status failureStatus = getStatus(StatusCode.RESPONDER_URI,
						StatusCode.AUTHN_FAILED_URI, failureMessage);
				Response response = buildResponse(authnRequest.getID(),
						relyingParty.getProviderID(), failureStatus);

				// XXX: TODO: send the response.

				return true;
			}

			// the user successfully authenticated. build an authentication
			// assertion.
			Response response = buildResponse(authnRequest.getID(),
					relyingParty.getProviderID(), buildStatus(
							StatusCode.SUCCESS_URI, null, null));

			// XXX: don't blindly copy conditions.
			Assertion assertion = buildAssertion(authnRequest.getSubject(),
					authnRequest.getConditions(), new String[] { relyingParty
							.getRelyingPartyID() });
			setAuthenticationStatement(assertion, loginCtx, authnRequest);

			response.getAssertions().add(assertion);

			// XXX: send the assertion

		} catch (AuthenticationRequestException ex) {

			StatusCode errorStatus = ex.getStatusCode();
			if (errorStatus == null) {
				// if no explicit status code was set, assume the error was in
				// the message.
				errorStatus = buildStatus(StatusCode.REQUESTER_URI, null, null);
				Response response = buildResponse(authnRequest.getID(),
						relyingParty.getProviderID(), failureStatus);
				// XXX: TODO: send the response.
			}

		}

		// build assertion
		// add assertion to response
		// send response

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

		// if the user has authenticated, their session will have a logincontext

		Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
		return (o == null);
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

		loginCtx = new Saml2LoginContext(authnRequest);
		loginCtx.setProfileHandlerURL(httpReq.getPathInfo());
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
			final LoginContext loginCtx, final AuthnRequest authnRequest)
			throws ServletException {

		// Build the AuthnCtx. We need to determine if the user was
		// authenticated
		// with an AuthnContextClassRef or a AuthnContextDeclRef
		AuthnContext authnCtx = buildAuthnCtx(authnRequest, loginCtx
				.getAuthenticationMethod());
		if (authnCtx == null) {
			log.error("Error respond to SAML 2 AuthnRequest "
					+ authnRequest.getID()
					+ " : Unable to determine authentication method");
		}

		AuthnStatement stmt = (AuthnStatement) authnStatementBuilder
				.buildObject(AuthnStatment.DEFAULT_ELEMENT_NAME);
		stmt.setAuthnInstant(loginCtx.getAuthenticationInstant());
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
			final RequestedAuthnContext requestedAuthnCtx, String authnMethod) {

		// this method assumes that only one URI will match.

		AuthnContext authnCtx = (AuthnCtx) authnContextBuilder
				.buildObject(AuthnContext.DEFAULT_ELEMENT_NAME);
		String authnMethod = loginCtx.getAuthenticationMethod();

		List<AuthnContextClassRef> authnClasses = ctx
				.getAuthnContextClassRefs();
		List<AuthnContextDeclRef> authnDeclRefs = ctx.getAuthnContextDeclRefs();

		if (authnClasses != null) {
			for (AuthnContextClassRef classRef : authnClasses) {
				if (classRef != null) {
					String s = classRef.getAuthnContextClassRef();
					if (s != null && authnMethod.equals(s)) {
						AuthnContextClassRef classRef = (AuthnContextClassRef) authnContextClassRefBuilder
								.buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
						authnCtx.setAuthnContextClassRef(classRef);
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
						AuthnContextDeclRef declRef = (AuthnContextDeclRef) authnContextDeclRefBuilder
								.buildObject(AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
						authnCtx.setAuthnContextDeclRef(declRef);
						return authnCtx;
					}
				}
			}
		}

		// no matches were found.
		return null;
	}

	/**
	 * Get the User's LoginContext.
	 * 
	 * @param httpSession
	 *            The user's HttpSession.
	 * 
	 * @return The user's LoginContext.
	 * 
	 * @throws ServletException
	 *             On error.
	 */
	protected LoginContext getLoginContext(final HttpSession httpSession)
			throws ServletException {

		Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
		if (o == null) {
			log.error("User's session does not contain a LoginContext object.");
			throw new ServletException(
					"User's session does not contain a LoginContext object.");
		}

		if (!(o instanceof LoginContext)) {
			log
					.error("Invalid login context object -- object is not an instance of LoginContext.");
			throw new ServletException("Invalid login context object.");
		}

		return (LoginContext) o;
		;
	}

	/**
	 * Verify the AuthnRequest is well-formed.
	 * 
	 * @param authnRequest
	 *            The user's SAML 2 AuthnRequest.
	 * 
	 * @throws AuthenticationRequestException
	 *             on error.
	 */
	protected void verifyAuthnRequest(final AuthnRequest authnRequest)
			throws AuthenticationRequestException {

		Status failureStatus;

		// The Web Browser SSO profile requires that the Issuer element is
		// present.
		Issuer issuer = authnRequest.getIssuer();
		if (issuer == null) {
			log.error("Malformed SAML 2 AuthnReq - missing Issuer element.");
			failureStatus = buildStatus(StatusCode.REQUESTER_URI, null,
					"SAML 2 AuthnRequest " + authnRequest.getID()
							+ " is malformed: It lacks an Issuer.");
			throw new AuthenticationRequestException(
					"AuthnRequest lacks an Issuer", failureStatus);
		}

		// Check if we are in scope to handle this AuthnRequest
		// XXX: confirm that SPProviderID is the field we want in the issuer
		if (!checkScope(authnRequest, issuer.getSPProvidedID())) {
			return false;
		}

		// XXX: run signature checks on authnRequest

		// verify that the AssertionConsumerService url is valid.
		AssertionConsumerService acsEndpoint = getAndVerifyACSEndpoint(
				authnRequest, relyingParty.getRelyingPartyID(), rpManager
						.getMetadataProvider());

		Subject subject = getAndVerifySubject(authnRequest, failureStatus);

		// check for nameID constraints.
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
		if (confMethods != null || confMethods.length > 0) {
			log
					.error("SAML 2 AuthnRequest "
							+ authnRequest.getID()
							+ " is malformed: It contains SubjectConfirmation elements.");
			failureStauts = buildStatus(
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
			if (i > acsList.length) {
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
		for (AssertionConumerService acs : acsList) {
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

		failureStatus = buildStatus(statusCodeBuilder.REQUESTER_URI, null,
				"Unable to validate AssertionConsumerService against metadata.");

		throw new AuthenticationRequestException(
				"Unabel to validate AssertionConsumerService against Metadata",
				failureStatus);
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
			return true;
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
				found = true;
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
