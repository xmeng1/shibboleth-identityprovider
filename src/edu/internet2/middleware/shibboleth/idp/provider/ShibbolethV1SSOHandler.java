/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.idp.provider;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLAuthorityBinding;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBrowserProfile;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import sun.misc.BASE64Decoder;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibBrowserProfile;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.InvalidClientDataException;

import edu.internet2.middleware.shibboleth.metadata.Endpoint;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.SPSSODescriptor;

/**
 * @author Walter Hoehn
 */
public class ShibbolethV1SSOHandler extends BaseHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(ShibbolethV1SSOHandler.class.getName());

	/**
	 * Required DOM-based constructor.
	 */
	public ShibbolethV1SSOHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws SAMLException, ServletException, IOException {

		// TODO attribute push?

		if (request == null) {
			log.error("Protocol Handler received a SAML Request, but is unable to handle it.");
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		}

		// Set attributes that are needed by the jsp
		request.setAttribute("shire", request.getParameter("shire"));
		request.setAttribute("target", request.getParameter("target"));

		try {
			// Ensure that we have the required data from the servlet container
			IdPProtocolSupport.validateEngineData(request);
			validateShibSpecificData(request);

			// Get the authN info
			String username = support.getIdPConfig().getAuthHeaderName().equalsIgnoreCase("REMOTE_USER") ? request
					.getRemoteUser() : request.getHeader(support.getIdPConfig().getAuthHeaderName());
			if ((username == null) || (username.equals(""))) { throw new InvalidClientDataException(
					"Unable to authenticate remote user"); }

			// Select the appropriate Relying Party configuration for the request
			RelyingParty relyingParty = null;
			String remoteProviderId = request.getParameter("providerId");
			// If the target did not send a Provider Id, then assume it is a Shib
			// 1.1 or older target
			if (remoteProviderId == null) {
				relyingParty = support.getServiceProviderMapper().getLegacyRelyingParty();
			} else if (remoteProviderId.equals("")) {
				throw new InvalidClientDataException("Invalid service provider id.");
			} else {
				log.debug("Remote provider has identified itself as: (" + remoteProviderId + ").");
				relyingParty = support.getServiceProviderMapper().getRelyingParty(remoteProviderId);
			}

			// Grab the metadata for the provider
			EntityDescriptor provider = support.lookup(relyingParty.getProviderId());

			// Determine the acceptance URL
			String acceptanceURL = request.getParameter("shire");

			// Make sure that the selected relying party configuration is appropriate for this
			// acceptance URL
			if (!relyingParty.isLegacyProvider()) {

				if (provider == null) {
					log.info("No metadata found for provider: (" + relyingParty.getProviderId() + ").");
					relyingParty = support.getServiceProviderMapper().getRelyingParty(null);

				} else {

					if (isValidAssertionConsumerURL(provider, acceptanceURL)) {
						log.info("Supplied consumer URL validated for this provider.");
					} else {
						log.error("Assertion consumer service URL (" + acceptanceURL + ") is NOT valid for provider ("
								+ relyingParty.getProviderId() + ").");
						throw new InvalidClientDataException("Invalid assertion consumer service URL.");
					}
				}
			}

			// Create SAML Name Identifier
			SAMLNameIdentifier nameId;
			try {
				nameId = support.getNameMapper().getNameIdentifierName(relyingParty.getHSNameFormatId(),
						new AuthNPrincipal(username), relyingParty, relyingParty.getIdentityProvider());
			} catch (NameIdentifierMappingException e) {
				log.error("Error converting principal to SAML Name Identifier: " + e);
				throw new SAMLException("Error converting principal to SAML Name Identifier.", e);
			}

			String authenticationMethod = request.getHeader("SAMLAuthenticationMethod");
			if (authenticationMethod == null || authenticationMethod.equals("")) {
				authenticationMethod = relyingParty.getDefaultAuthMethod().toString();
				log.debug("User was authenticated via the default method for this relying party ("
						+ authenticationMethod + ").");
			} else {
				log.debug("User was authenticated via the method (" + authenticationMethod + ").");
			}

			// TODO Provide a mechanism for the authenticator to specify the auth time
			SAMLAssertion[] assertions = generateAssertion(request, relyingParty, provider, nameId,
					authenticationMethod, new Date(System.currentTimeMillis()));

			// TODO do assertion signing for artifact stuff

			// SAML Artifact profile
			if (useArtifactProfile(provider, acceptanceURL)) {
				log.debug("Responding with Artifact profile.");

				// Create artifacts for each assertion
				ArrayList artifacts = new ArrayList();
				for (int i = 0; i < assertions.length; i++) {
					artifacts.add(support.getArtifactMapper().generateArtifact(assertions[i], relyingParty));
				}

				// Assemble the query string
				StringBuffer destination = new StringBuffer(acceptanceURL);
				destination.append("?TARGET=");

				destination.append(URLEncoder.encode(request.getParameter("target"), "UTF-8"));

				Iterator iterator = artifacts.iterator();
				StringBuffer artifactBuffer = new StringBuffer(); // Buffer for the transaction log
				while (iterator.hasNext()) {
					destination.append("&SAMLart=");
					String artifact = (String) iterator.next();

					destination.append(URLEncoder.encode(artifact, "UTF-8"));
					artifactBuffer.append("(" + artifact + ")");

				}
				log.debug("Redirecting to (" + destination.toString() + ").");
				response.sendRedirect(destination.toString()); // Redirect to the artifact receiver

				support.getTransactionLog().info(
						"Assertion artifact(s) (" + artifactBuffer.toString() + ") issued to provider ("
								+ relyingParty.getIdentityProvider().getProviderId() + ") on behalf of principal ("
								+ username + "). Name Identifier: (" + nameId.getName()
								+ "). Name Identifier Format: (" + nameId.getFormat() + ").");

				// SAML POST profile
			} else {
				log.debug("Responding with POST profile.");
				request.setAttribute("acceptanceURL", acceptanceURL);
				request.setAttribute("target", request.getParameter("target"));

				SAMLResponse samlResponse = new SAMLResponse(null, acceptanceURL, Arrays.asList(assertions), null);
				IdPProtocolSupport.addSignatures(samlResponse, relyingParty, provider, true);
				createPOSTForm(request, response, samlResponse.toBase64());

				// Make transaction log entry
				if (relyingParty.isLegacyProvider()) {
					support.getTransactionLog().info(
							"Authentication assertion issued to legacy provider (SHIRE: "
									+ request.getParameter("shire") + ") on behalf of principal (" + username
									+ ") for resource (" + request.getParameter("target") + "). Name Identifier: ("
									+ nameId.getName() + "). Name Identifier Format: (" + nameId.getFormat() + ").");
				} else {
					support.getTransactionLog().info(
							"Authentication assertion issued to provider ("
									+ relyingParty.getIdentityProvider().getProviderId() + ") on behalf of principal ("
									+ username + "). Name Identifier: (" + nameId.getName()
									+ "). Name Identifier Format: (" + nameId.getFormat() + ").");
				}
			}
		} catch (InvalidClientDataException e) {
			throw new SAMLException(SAMLException.RESPONDER, e.getMessage());
		}
		return null;
	}

	private SAMLAssertion[] generateAssertion(HttpServletRequest request, RelyingParty relyingParty,
			EntityDescriptor provider, SAMLNameIdentifier nameId, String authenticationMethod, Date authTime)
			throws SAMLException, IOException {

		Document doc = org.opensaml.XML.parserPool.newDocument();

		// Determine the correct audiences
		ArrayList audiences = new ArrayList();
		if (relyingParty.getProviderId() != null) {
			audiences.add(relyingParty.getProviderId());
		}
		if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
			audiences.add(relyingParty.getName());
		}

		// Determine the correct issuer
		String issuer = null;
		if (relyingParty.isLegacyProvider()) {

			log.debug("Service Provider is running Shibboleth <= 1.1. Using old style issuer.");
			if (relyingParty.getIdentityProvider().getSigningCredential() == null
					|| relyingParty.getIdentityProvider().getSigningCredential().getX509Certificate() == null) { throw new SAMLException(
					"Cannot serve legacy style assertions without an X509 certificate"); }
			issuer = ShibBrowserProfile.getHostNameFromDN(relyingParty.getIdentityProvider().getSigningCredential()
					.getX509Certificate().getSubjectX500Principal());
			if (issuer == null || issuer.equals("")) { throw new SAMLException(
					"Error parsing certificate DN while determining legacy issuer name."); }

		} else {
			issuer = relyingParty.getIdentityProvider().getProviderId();
		}

		// For compatibility with pre-1.2 shibboleth targets, include a pointer to the AA
		ArrayList bindings = new ArrayList();
		if (relyingParty.isLegacyProvider()) {

			SAMLAuthorityBinding binding = new SAMLAuthorityBinding(SAMLBinding.SOAP, relyingParty.getAAUrl()
					.toString(), new QName(org.opensaml.XML.SAMLP_NS, "AttributeQuery"));
			bindings.add(binding);
		}

		// Create the authN assertion
		Vector conditions = new Vector(1);
		if (audiences != null && audiences.size() > 0) conditions.add(new SAMLAudienceRestrictionCondition(audiences));

		String[] confirmationMethods = {SAMLSubject.CONF_BEARER};
		SAMLSubject subject = new SAMLSubject(nameId, Arrays.asList(confirmationMethods), null, null);

		SAMLStatement[] statements = {new SAMLAuthenticationStatement(subject, authenticationMethod, authTime, request
				.getRemoteAddr(), null, bindings)};

		SAMLAssertion[] assertions = {new SAMLAssertion(issuer, new Date(System.currentTimeMillis()), new Date(System
				.currentTimeMillis() + 300000), conditions, null, Arrays.asList(statements))};

		if (log.isDebugEnabled()) {
			log.debug("Dumping generated SAML Assertions:"
					+ System.getProperty("line.separator")
					+ new String(new BASE64Decoder().decodeBuffer(new String(assertions[0].toBase64(), "ASCII")),
							"UTF8"));
		}

		return assertions;
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#getHandlerName()
	 */
	public String getHandlerName() {

		return "Shibboleth v1.x SSO";
	}

	private void validateShibSpecificData(HttpServletRequest request) throws InvalidClientDataException {

		if (request.getParameter("target") == null || request.getParameter("target").equals("")) { throw new InvalidClientDataException(
				"Invalid data from Service Provider: no target URL received."); }
		if ((request.getParameter("shire") == null) || (request.getParameter("shire").equals(""))) { throw new InvalidClientDataException(
				"Invalid data from Service Provider: No acceptance URL received."); }
	}

	private static void createPOSTForm(HttpServletRequest req, HttpServletResponse res, byte[] buf) throws IOException,
			ServletException {

		// Hardcoded to ASCII to ensure Base64 encoding compatibility
		req.setAttribute("assertion", new String(buf, "ASCII"));

		if (log.isDebugEnabled()) {
			try {
				log.debug("Dumping generated SAML Response:" + System.getProperty("line.separator")
						+ new String(new BASE64Decoder().decodeBuffer(new String(buf, "ASCII")), "UTF8"));
			} catch (IOException e) {
				log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
			}
		}

		RequestDispatcher rd = req.getRequestDispatcher("/IdP.jsp");
		rd.forward(req, res);
	}

	private static boolean useArtifactProfile(EntityDescriptor provider, String acceptanceURL) {

		// Default to POST if we have no metadata
		if (provider == null) { return false; }

		// Default to POST if we have incomplete metadata
		SPSSODescriptor sp = provider.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
		if (sp == null) { return false; }

		// Look at the bindings.. prefer POST if we have multiple
		Iterator endpoints = sp.getAssertionConsumerServiceManager().getEndpoints();
		while (endpoints.hasNext()) {
			Endpoint ep = (Endpoint) endpoints.next();
			if (acceptanceURL.equals(ep.getLocation()) && SAMLBrowserProfile.PROFILE_POST_URI.equals(ep.getBinding())) { return false; }
			if (acceptanceURL.equals(ep.getLocation())
					&& SAMLBrowserProfile.PROFILE_ARTIFACT_URI.equals(ep.getBinding())) { return true; }
		}

		// Default to POST if we have incomplete metadata
		return false;
	}

	private static boolean isValidAssertionConsumerURL(EntityDescriptor provider, String shireURL)
			throws InvalidClientDataException {

		SPSSODescriptor sp = provider.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
		if (sp == null) {
			log.info("Inappropriate metadata for provider.");
			return false;
		}

		Iterator endpoints = sp.getAssertionConsumerServiceManager().getEndpoints();
		while (endpoints.hasNext()) {
			if (shireURL.equals(((Endpoint) endpoints.next()).getLocation())) { return true; }
		}
		log.info("Supplied consumer URL not found in metadata.");
		return false;
	}
}