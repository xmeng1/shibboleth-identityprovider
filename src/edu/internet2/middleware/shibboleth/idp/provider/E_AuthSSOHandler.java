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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.InvalidClientDataException;

/**
 * @author Walter Hoehn
 */
public class E_AuthSSOHandler extends SSOHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(E_AuthSSOHandler.class.getName());
	private final String name = "EAuth";
	private final String eAuthPortal = "http://eauth.firstgov.gov/service/select";
	private final String eAuthFed = "urn:mace:shibboleth:eAuthFed";
	private String csid;

	// TODO validate that the target wants artifact, since it is required for this profile
	// TODO validate that we aren't using signatures
	// TODO validate that we are using the right nameIdentifier format
	// TODO more robust attribute values before we ship
	/**
	 * Required DOM-based constructor.
	 */
	public E_AuthSSOHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
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
		if (request != null) {
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

		try {
			validateEngineData(request);
		} catch (InvalidClientDataException e1) {
			// TODO Auto-generated catch block
		}

		// TODO figure this out
		RelyingParty relyingParty = null;
		SAMLNameIdentifier nameId = null;
		String authenticationMethod = null;
		Date authTime = null;

		Document doc = org.opensaml.XML.parserPool.newDocument();
		ArrayList audiences = new ArrayList();
		if (relyingParty.getProviderId() != null) {
			audiences.add(relyingParty.getProviderId());
		}
		if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
			audiences.add(relyingParty.getName());
		}
		String issuer = relyingParty.getIdentityProvider().getProviderId();
		Vector conditions = new Vector(1);
		if (audiences != null && audiences.size() > 0) {
			conditions.add(new SAMLAudienceRestrictionCondition(audiences));
		}

		// TODO need to pull this out into the generic artifact handling
		String[] confirmationMethods = {SAMLSubject.CONF_ARTIFACT};
		SAMLSubject subject = new SAMLSubject(nameId, Arrays.asList(confirmationMethods), null, null);
		// TODO pull from authN system? or make configurable
		ArrayList attributes = new ArrayList();
		attributes.add(new SAMLAttribute("assuranceLevel", "http://eauthentication.gsa.gov/federated/attribute", null,
				0, Arrays.asList(new String[]{"2"})));

		// TODO Hack Alert!!!
		// Pull attributes from AA
		String hackFullName = null;
		if (nameId.getName().startsWith("uid=tomcat")) {
			hackFullName = "Tomcat Test User";
		} else if (nameId.getName().startsWith("uid=nfaut")) {
			hackFullName = "Nathan Faut";
		} else if (nameId.getName().startsWith("uid=wassa")) {
			hackFullName = "Walter F. Hoehn, Jr.";
		} else if (nameId.getName().startsWith("uid=mtebo")) {
			hackFullName = "Matt Tebo";
		} else if (nameId.getName().startsWith("uid=dblanchard")) {
			hackFullName = "Deb Blanchard";
		} else if (nameId.getName().startsWith("uid=rweiser")) {
			hackFullName = "Russ Weiser";
		} else if (nameId.getName().startsWith("uid=scarmody")) {
			hackFullName = "Steven Carmody";
		}
		attributes.add(new SAMLAttribute("commonName", "http://eauthentication.gsa.gov/federated/attribute", null, 0,
				Arrays.asList(new String[]{hackFullName})));
		attributes.add(new SAMLAttribute("csid", "http://eauthentication.gsa.gov/federated/attribute", null, 0, Arrays
				.asList(new String[]{csid})));
		try {
			SAMLStatement[] statements = {
					new SAMLAuthenticationStatement(subject, authenticationMethod, authTime, request.getRemoteAddr(),
							null, null), new SAMLAttributeStatement((SAMLSubject) subject.clone(), attributes)};
			SAMLAssertion[] assertions = {new SAMLAssertion(issuer, new Date(System.currentTimeMillis()), new Date(
					System.currentTimeMillis() + 300000), conditions, null, Arrays.asList(statements))};
			if (log.isDebugEnabled()) {
				log.debug("Dumping generated SAML Assertions:" + System.getProperty("line.separator")
						+ assertions[0].toString());
			}
			return null;
		} catch (CloneNotSupportedException e) { // TODO handle return null; } }

		}

		return null;

	}

	/*
	 * EAuthProfileHandler(String csid) throws ShibbolethConfigurationException { if (csid == null) { throw new
	 * ShibbolethConfigurationException( "EAuth support is enabled, but no (csid) parameter has been configured."); }
	 * this.csid = csid; }
	 */

	/*
	 * String getRemoteProviderId(HttpServletRequest req) { return req.getParameter("aaid"); }
	 */

	/*
	 * String getSAMLTargetParameter(HttpServletRequest request, RelyingParty relyingParty, Provider provider) {
	 * ProviderRole[] roles = provider.getRoles(); if (roles.length == 0) { log.error("Inappropriate metadata for EAuth
	 * provider."); return null; } for (int i = 0; roles.length > i; i++) { if (roles[i] instanceof SPProviderRole) {
	 * return ((SPProviderRole) roles[i]).getTarget(); } } log.error("Inappropriate metadata for EAuth provider.");
	 * return null; }
	 */

	/*
	 * internet2.middleware.shibboleth.hs.HSRelyingParty) String getAcceptanceURL(HttpServletRequest request,
	 * HSRelyingParty relyingParty, Provider provider) throws InvalidClientDataException { //The EAuth profile requires
	 * metadata, since the assertion consumer is not supplied as a request parameter if (provider == null) {
	 * log.error("Unkown requesting service provider (" + relyingParty.getProviderId() + ")."); throw new
	 * InvalidClientDataException("Unkown requesting service provider."); } //Pull the consumer URL from the metadata
	 * ProviderRole[] roles = provider.getRoles(); if (roles.length == 0) { log.info("Inappropriate metadata for
	 * provider: no roles specified."); throw new InvalidClientDataException("Invalid metadata for requesting service
	 * provider."); } for (int i = 0; roles.length > i; i++) { if (roles[i] instanceof SPProviderRole) { Endpoint[]
	 * endpoints = ((SPProviderRole) roles[i]).getAssertionConsumerServiceURLs(); if (endpoints.length > 0) { return
	 * endpoints[0].getLocation(); } } } log.info("Inappropriate metadata for provider: no roles specified."); throw new
	 * InvalidClientDataException("Invalid metadata for requesting service provider."); }
	 */

}