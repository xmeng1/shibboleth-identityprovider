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
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.opensaml.artifact.Artifact;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.InvalidClientDataException;
import edu.internet2.middleware.shibboleth.metadata.Endpoint;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.SPSSODescriptor;

/**
 * <code>ProtocolHandler</code> implementation that responds to SSO flows as specified in "E-Authentication Interface
 * Specifications for the SAML Artifact Profile ".
 * 
 * @author Walter Hoehn
 */
public class E_AuthSSOHandler extends SSOHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(E_AuthSSOHandler.class.getName());
	private String eAuthPortal = "http://eauth.firstgov.gov/service/select";
	private String eAuthError = "http://eauth.firstgov.gov/service/error";
	private String csid;

	/**
	 * Required DOM-based constructor.
	 */
	public E_AuthSSOHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
		csid = config.getAttribute("csid");
		if (csid == null || csid.equals("")) {
			log.error("(csid) attribute is required for the " + getHandlerName() + "protocol handler.");
			throw new ShibbolethConfigurationException("Unable to initialize protocol handler.");
		}

		String portal = config.getAttribute("eAuthPortal");
		if (portal != null && !portal.equals("")) {
			eAuthPortal = portal;
		}

		String error = config.getAttribute("eAuthError");
		if (error != null && !error.equals("")) {
			eAuthError = portal;
		}
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler#getHandlerName()
	 */
	public String getHandlerName() {

		return "E-Authentication SSO";
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse, org.opensaml.SAMLRequest,
	 *      edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport)
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws SAMLException, IOException, ServletException {

		// Sanity check
		if (samlRequest != null) {
			log.error("Protocol Handler received a SAML Request, but is unable to handle it.");
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		}

		// If no aaid is specified, redirect to the eAuth portal
		if (request.getParameter("aaid") == null || request.getParameter("aaid").equals("")) {
			log.debug("Received an E-Authentication request with no (aaid) parameter.  "
					+ "Redirecting to the E-Authentication portal.");
			response.sendRedirect(eAuthPortal + "?csid=" + csid);
			return null;
		}

		// FUTURE at some point this needs to be integrated with SAML2 session reset
		// If session reset was requested, delete the session and re-direct back
		// Note, this only works with servler form-auth
		String reAuth = request.getParameter("sessionreset");
		if (reAuth != null && reAuth.equals("1")) {
			log.debug("E-Authebtication session reset requested.");
			Cookie session = new Cookie("JSESSIONID", null);
			session.setMaxAge(0);
			response.addCookie(session);

			response.sendRedirect(request.getRequestURI()
					+ (request.getQueryString() != null ? "?"
							+ request.getQueryString().replaceAll("(^sessionreset=1&?|&?sessionreset=1)", "") : ""));
			return null;
		}
		// Sanity check
		try {
			validateEngineData(request);
		} catch (InvalidClientDataException e) {
			throw new SAMLException(SAMLException.RESPONDER, e.getMessage());
		}

		// Get the authN info
		String username = support.getIdPConfig().getAuthHeaderName().equalsIgnoreCase("REMOTE_USER") ? request
				.getRemoteUser() : request.getHeader(support.getIdPConfig().getAuthHeaderName());
		if ((username == null) || (username.equals(""))) {
			log.error("Unable to authenticate remote user.");
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		}
		AuthNPrincipal principal = new AuthNPrincipal(username);

		// Select the appropriate Relying Party configuration for the request
		String remoteProviderId = request.getParameter("aaid");
		log.debug("Remote provider has identified itself as: (" + remoteProviderId + ").");
		RelyingParty relyingParty = support.getServiceProviderMapper().getRelyingParty(remoteProviderId);

		if (relyingParty == null || relyingParty.isLegacyProvider()) {
			log.error("Unable to identify appropriate relying party configuration.");
			eAuthError(response, 30, remoteProviderId, csid);
			return null;
		}

		// Lookup the provider in the metadata
		EntityDescriptor entity = support.lookup(relyingParty.getProviderId());
		if (entity == null) {
			log.error("No metadata found for EAuth provider.");
			eAuthError(response, 30, remoteProviderId, csid);
			return null;
		}
		SPSSODescriptor role = entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");
		if (role == null) {
			log.error("Inappropriate metadata for EAuth provider.");
			eAuthError(response, 30, remoteProviderId, csid);
			return null;
		}

		// The EAuth profile requires metadata, since the assertion consumer is not supplied as a request parameter
		// Pull the consumer URL from the metadata
		Iterator endpoints = role.getAssertionConsumerServiceManager().getEndpoints();
		if (endpoints == null || !endpoints.hasNext()) {
			log.error("Inappropriate metadata for provider: no roles specified.");
			eAuthError(response, 30, remoteProviderId, csid);
			return null;
		}
		String consumerURL = ((Endpoint) endpoints.next()).getLocation();
		log.debug("Assertion Consumer URL provider: " + consumerURL);

		// Create SAML Name Identifier & Subject
		SAMLNameIdentifier nameId;
		try {
			// TODO verify that the nameId is the right format here and error if not
			nameId = support.getNameMapper().getNameIdentifierName(relyingParty.getHSNameFormatId(), principal,
					relyingParty, relyingParty.getIdentityProvider());
		} catch (NameIdentifierMappingException e) {
			log.error("Error converting principal to SAML Name Identifier: " + e);
			eAuthError(response, 60, remoteProviderId, csid);
			return null;
		}

		String[] confirmationMethods = {SAMLSubject.CONF_ARTIFACT};
		SAMLSubject authNSubject = new SAMLSubject(nameId, Arrays.asList(confirmationMethods), null, null);

		// Determine AuthN method
		String authenticationMethod = request.getHeader("SAMLAuthenticationMethod");
		if (authenticationMethod == null || authenticationMethod.equals("")) {
			authenticationMethod = relyingParty.getDefaultAuthMethod().toString();
			log.debug("User was authenticated via the default method for this relying party (" + authenticationMethod
					+ ").");
		} else {
			log.debug("User was authenticated via the method (" + authenticationMethod + ").");
		}

		String issuer = relyingParty.getIdentityProvider().getProviderId();

		log.info("Resolving attributes.");
		List attributes = null;
		try {
			attributes = Arrays.asList(support.getReleaseAttributes(principal, relyingParty, relyingParty.getProviderId(), null));
		} catch (AAException e1) {
			log.error("Error resolving attributes: " + e1);
			eAuthError(response, 90, remoteProviderId, csid);
			return null;
		}
		log.info("Found " + attributes.size() + " attribute(s) for " + principal.getName());

		// Bail if we didn't get any attributes
		if (attributes == null || attributes.size() < 1) {
			log.error("Attribute resolver did not return any attributes. "
					+ " The E-Authentication profile's minimum attribute requirements were not met.");
			eAuthError(response, 60, remoteProviderId, csid);
			return null;

			// OK, we got attributes back, package them as required for eAuth and combine them with the authN data in an
			// assertion
		} else {
			try {
				attributes = repackageForEauth(attributes);
			} catch (SAMLException e) {
				eAuthError(response, 90, remoteProviderId, csid);
				return null;
			}

			// Put all attributes into an assertion
			try {
				// TODO provide a way to override authN time
				SAMLStatement attrStatement = new SAMLAttributeStatement((SAMLSubject) authNSubject.clone(), attributes);
				SAMLStatement[] statements = {
						new SAMLAuthenticationStatement(authNSubject, authenticationMethod, new Date(System
								.currentTimeMillis()), request.getRemoteAddr(), null, null), attrStatement};
				SAMLAssertion assertion = new SAMLAssertion(issuer, new Date(System.currentTimeMillis()), new Date(
						System.currentTimeMillis() + 300000), null, null, Arrays.asList(statements));
				if (log.isDebugEnabled()) {
					log.debug("Dumping generated SAML Assertion:" + System.getProperty("line.separator")
							+ assertion.toString());
				}

				// Redirect to agency application
				try {
					respondWithArtifact(response, support, consumerURL, principal, assertion, nameId, role,
							relyingParty);
					return null;
				} catch (SAMLException e) {
					eAuthError(response, 90, remoteProviderId, csid);
					return null;
				}

			} catch (CloneNotSupportedException e) {
				log.error("An error was encountered while generating assertion: " + e);
				eAuthError(response, 90, remoteProviderId, csid);
				return null;
			}
		}
	}

	private void respondWithArtifact(HttpServletResponse response, IdPProtocolSupport support, String acceptanceURL,
			Principal principal, SAMLAssertion assertion, SAMLNameIdentifier nameId, SPSSODescriptor descriptor,
			RelyingParty relyingParty) throws SAMLException, IOException {

		// Create artifacts for each assertion
		ArrayList artifacts = new ArrayList();

		artifacts.add(support.getArtifactMapper().generateArtifact(assertion, relyingParty));

		String target = relyingParty.getDefaultTarget();
		if (target == null || target.equals("")) {
			log.error("No default target found.  Relying Party elements corresponding to "
					+ "E-Authentication providers must have a (defaultTarget) attribute specified.");
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		}

		// Assemble the query string
		StringBuffer destination = new StringBuffer(acceptanceURL);
		destination.append("?TARGET=");
		destination.append(URLEncoder.encode(target, "UTF-8"));
		Iterator iterator = artifacts.iterator();
		StringBuffer artifactBuffer = new StringBuffer(); // Buffer for the transaction log

		// Construct the artifact query parameter
		while (iterator.hasNext()) {
			Artifact artifact = (Artifact) iterator.next();
			artifactBuffer.append("(" + artifact.encode() + ")");
			destination.append("&SAMLart=");
			destination.append(URLEncoder.encode(artifact.encode(), "UTF-8"));
		}

		log.debug("Redirecting to (" + destination.toString() + ").");
		response.sendRedirect(destination.toString()); // Redirect to the artifact receiver
		support.getTransactionLog().info(
				"Assertion artifact(s) (" + artifactBuffer.toString() + ") issued to E-Authentication provider ("
						+ relyingParty.getProviderId() + ") on behalf of principal ("
						+ principal.getName() + "). Name Identifier: (" + nameId.getName()
						+ "). Name Identifier Format: (" + nameId.getFormat() + ").");

	}

	private List repackageForEauth(List attributes) throws SAMLException {

		ArrayList  writeable = new ArrayList(attributes); 
		// Bail if we didn't get a commonName, because it is required by the profile
		SAMLAttribute commonName = getAttribute("commonName", writeable);
		if (commonName == null) {
			log.error("The attribute resolver did not return a (commonName) attribute, "
					+ " which is required for the E-Authentication profile.");
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		} else {
			// This namespace is required by the eAuth profile
			commonName.setNamespace("http://eauthentication.gsa.gov/federated/attribute");
			// TODO Maybe the resolver should set this
		}
		writeable.add(new SAMLAttribute("csid", "http://eauthentication.gsa.gov/federated/attribute", null, 0, Arrays
				.asList(new String[]{csid})));
		// TODO pull from authN system? or make configurable
		writeable.add(new SAMLAttribute("assuranceLevel", "http://eauthentication.gsa.gov/federated/attribute", null,
				0, Arrays.asList(new String[]{"2"})));
		return writeable;
	}

	private SAMLAttribute getAttribute(String name, List attributes) {

		Iterator iterator = attributes.iterator();
		while (iterator.hasNext()) {
			SAMLAttribute attribute = (SAMLAttribute) iterator.next();
			if (attribute.getName().equals(name)) { return attribute; }
		}
		return null;
	}

	private void eAuthError(HttpServletResponse response, int code, String aaid, String csid) throws IOException {

		log.info("Redirecting to E-Authentication error page.");
		response.sendRedirect(eAuthError + "?aaid=" + aaid + "&csid=" + csid + "&errcode=" + code);
	}
}