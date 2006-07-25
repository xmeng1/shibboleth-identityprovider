/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.provider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLConfig;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.opensaml.SAMLSubjectStatement;
import org.opensaml.XML;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.InvalidClientDataException;

/**
 * <code>ProtocolHandler</code> implementation that responds to ADFS SSO flows as specified in "WS-Federation: Passive
 * Requestor Interoperability Profiles".
 * 
 * @author Walter Hoehn
 */
public class ADFS_SSOHandler extends SSOHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(ADFS_SSOHandler.class.getName());
	private static final String WA = "wsignin1.0";
	private static final String WS_FED_PROTOCOL_ENUM = "http://schemas.xmlsoap.org/ws/2003/07/secext";
	private static final Collection SUPPORTED_IDENTIFIER_FORMATS = Arrays.asList(new String[]{
			"urn:oasis:names:tc:SAML:1.1nameid-format:emailAddress", "http://schemas.xmlsoap.org/claims/UPN",
			"http://schemas.xmlsoap.org/claims/CommonName"});
	private static final String CLAIMS_URI = "http://schemas.xmlsoap.org/claims";

	/**
	 * Required DOM-based constructor.
	 */
	public ADFS_SSOHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws SAMLException, ServletException, IOException {

		if (request == null) {
			log.error("Protocol Handler received a SAML Request, but is unable to handle it.");
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		}

		// Set attributes that are needed by the jsp
		// ADFS spec says always send (wa)
		request.setAttribute("wa", ADFS_SSOHandler.WA);
		// Passthru (wctx) if we get one
		if (request.getParameter("wctx") != null && !request.getParameter("wctx").equals("")) {
			request.setAttribute("wctx", request.getParameter("wctx"));
		}

		try {
			// Ensure that we have the required data from the servlet container
			validateEngineData(request);
			validateAdfsSpecificData(request);

			// Get the authN info
			String username = support.getIdPConfig().getAuthHeaderName().equalsIgnoreCase("REMOTE_USER") ? request
					.getRemoteUser() : request.getHeader(support.getIdPConfig().getAuthHeaderName());
			if ((username == null) || (username.equals(""))) { throw new InvalidClientDataException(
					"Unauthenticated principal. This protocol handler requires that authentication information be "
							+ "provided from the servlet container."); }
			LocalPrincipal principal = new LocalPrincipal(username);

			// Select the appropriate Relying Party configuration for the request
			String remoteProviderId = request.getParameter("wtrealm");
			log.debug("Remote provider has identified itself as: (" + remoteProviderId + ").");
			RelyingParty relyingParty = support.getServiceProviderMapper().getRelyingParty(remoteProviderId);

			// Grab the metadata for the provider
			EntityDescriptor descriptor = null;
			try {
				descriptor = support.getEntityDescriptor(relyingParty.getProviderId());
			} catch (MetadataProviderException e1) {
				log.error("Encountered an error while looking up metadata: " + e1);
			}

			if (descriptor == null) {
				log.info("No metadata found for provider: (" + relyingParty.getProviderId() + ").");
				throw new InvalidClientDataException(
						"The specified Service Provider is unkown to this Identity Provider.");
			}

			// Make sure we have proper WS-Fed metadata
			SPSSODescriptor sp = descriptor.getSPSSODescriptor(ADFS_SSOHandler.WS_FED_PROTOCOL_ENUM);
			if (sp == null) {
				log.info("Inappropriate metadata for provider: no WS-Federation binding.");
				throw new InvalidClientDataException(
						"Unable to communicate with the specified Service Provider via this protocol.");
			}

			// If an acceptance URL was supplied, validate it
			String acceptanceURL = request.getParameter("wreply");
			if (acceptanceURL != null && !acceptanceURL.equals("")) {
				if (isValidAssertionConsumerURL(sp, acceptanceURL)) {
					log.info("Supplied consumer URL validated for this provider.");
				} else {
					log.error("Assertion consumer service URL (" + acceptanceURL + ") is NOT valid for provider ("
							+ relyingParty.getProviderId() + ").");
					throw new InvalidClientDataException("Invalid assertion consumer service URL.");
				}
				// if none was supplied, pull one from the metadata

			} else {
				Endpoint endpoint = lookupAssertionConsumerService(sp);
				if (endpoint == null || endpoint.getLocation() == null) {
					log.error("No Assertion consumer service URL is available for provider ("
							+ relyingParty.getProviderId() + ") via request the SSO request or the metadata.");
					throw new InvalidClientDataException("Unable to determine assertion consumer service URL.");
				}
				acceptanceURL = endpoint.getLocation();
			}
			// Needed for the form
			request.setAttribute("wreply", acceptanceURL);

			// Create SAML Name Identifier & Subject
			SAMLNameIdentifier nameId;
			try {
				nameId = getNameIdentifier(support.getNameMapper(), principal, relyingParty, descriptor);
				// ADFS spec limits which name identifier formats can be used
				if (!ADFS_SSOHandler.SUPPORTED_IDENTIFIER_FORMATS.contains(nameId.getFormat())) {
					log.error("SAML Name Identifier format (" + nameId.getFormat()
							+ ") is inappropriate for use with ADFS provider.");
					throw new SAMLException(
							"Error converting principal to SAML Name Identifier: Invalid ADFS Name Identifier format.");
				}

			} catch (NameIdentifierMappingException e) {
				log.error("Error converting principal to SAML Name Identifier: " + e);
				throw new SAMLException("Error converting principal to SAML Name Identifier.", e);
			}

			// ADFS profile requires an authentication method
			String authenticationMethod = request.getHeader("SAMLAuthenticationMethod");
			if (authenticationMethod == null || authenticationMethod.equals("")) {
				authenticationMethod = relyingParty.getDefaultAuthMethod().toString();
				log.debug("User was authenticated via the default method for this relying party ("
						+ authenticationMethod + ").");
			} else {
				log.debug("User was authenticated via the method (" + authenticationMethod + ").");
			}

			SAMLSubject authNSubject = new SAMLSubject(nameId, null, null, null);

			// We always do POST with ADFS
			respondWithPOST(request, response, support, principal, relyingParty, descriptor, acceptanceURL, nameId,
					authenticationMethod, authNSubject);

		} catch (InvalidClientDataException e) {
			throw new SAMLException(SAMLException.RESPONDER, e.getMessage());
		} catch (SecurityTokenResponseException e) {
			throw new SAMLException(SAMLException.RESPONDER, e.getMessage());
		}
		return null;
	}

	private Endpoint lookupAssertionConsumerService(SPSSODescriptor sp) {

		// Grab the first endpoin we find with an ADFS protocol binding
		List<AssertionConsumerService> acs = sp.getAssertionConsumerServices();
		for (AssertionConsumerService service : acs) {
			if (ADFS_SSOHandler.WS_FED_PROTOCOL_ENUM.equals(service.getBinding())) { return service; }
		}

		return null;
	}

	private void respondWithPOST(HttpServletRequest request, HttpServletResponse response, IdPProtocolSupport support,
			LocalPrincipal principal, RelyingParty relyingParty, EntityDescriptor descriptor, String acceptanceURL,
			SAMLNameIdentifier nameId, String authenticationMethod, SAMLSubject authNSubject) throws SAMLException,
			IOException, ServletException, SecurityTokenResponseException {

		// We should always send a single token (SAML assertion)
		SAMLAssertion assertion = generateAssertion(request, relyingParty, descriptor, nameId, authenticationMethod,
				getAuthNTime(request), authNSubject);

		generateAttributes(support, principal, relyingParty, assertion, request);

		// ADFS spec says assertions should always be signed
		support.signAssertions((SAMLAssertion[]) new SAMLAssertion[]{assertion}, relyingParty);

		// Wrap assertion in security token response and create form
		createPOSTForm(request, response, new SecurityTokenResponse(assertion, relyingParty.getProviderId()));

		// Make transaction log entry
		support.getTransactionLog().info(
				"ADFS security token issued to provider (" + relyingParty.getProviderId()
						+ ") on behalf of principal (" + principal.getName() + ").");
	}

	private void generateAttributes(IdPProtocolSupport support, LocalPrincipal principal, RelyingParty relyingParty,
			SAMLAssertion assertion, HttpServletRequest request) throws SAMLException {

		try {
			Collection<? extends SAMLAttribute> attributes = support.getReleaseAttributes(principal, relyingParty,
					relyingParty.getProviderId());
			log.info("Found " + attributes.size() + " attribute(s) for " + principal.getName());

			// Bail if we didn't get any attributes
			if (attributes == null || attributes.size() < 1) {
				log.info("No attributes resolved.");
				return;
			}

			// The ADFS spec recommends that all attributes have this URI, but it doesn't require it
			for (SAMLAttribute attribute : attributes) {
				if (!attribute.getNamespace().equals(CLAIMS_URI)) {
					log.warn("It is recommended that all attributes sent via the ADFS SSO handler "
							+ "have a namespace of (" + CLAIMS_URI + ").  The attribute (" + attribute.getName()
							+ ") has a namespace of (" + attribute.getNamespace() + ").");
				}
			}

			// Reference requested subject
			SAMLSubject attrSubject = (SAMLSubject) ((SAMLSubjectStatement) assertion.getStatements().next())
					.getSubject().clone();

			// ADFS spec says to include authN and attribute statements in the same assertion
			log.debug("Merging attributes into existing authn assertion");
			assertion.addStatement(new SAMLAttributeStatement(attrSubject, Arrays.asList(attributes)));

			if (log.isDebugEnabled()) {
				log.debug("Dumping combined Assertion:" + System.getProperty("line.separator") + assertion.toString());
			}

		} catch (AAException e) {
			log.error("An error was encountered while generating assertion for attribute push: " + e);
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		} catch (CloneNotSupportedException e) {
			log.error("An error was encountered while generating assertion for attribute push: " + e);
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		}
	}

	private SAMLAssertion generateAssertion(HttpServletRequest request, RelyingParty relyingParty,
			EntityDescriptor descriptor, SAMLNameIdentifier nameId, String authenticationMethod, Date authTime,
			SAMLSubject subject) throws SAMLException, IOException {

		// Bearer method is recommended by the ADFS spec
		subject.addConfirmationMethod(SAMLSubject.CONF_BEARER);

		// ADFS spec requires a single audience of the SP
		ArrayList<String> audiences = new ArrayList<String>();
		if (relyingParty.getProviderId() != null) {
			audiences.add(relyingParty.getProviderId());
		}
		Vector<SAMLCondition> conditions = new Vector<SAMLCondition>(1);
		if (audiences != null && audiences.size() > 0) conditions.add(new SAMLAudienceRestrictionCondition(audiences));

		// Determine the correct issuer
		String issuer = relyingParty.getIdentityProvider().getProviderId();

		// Create the assertion
		// NOTE the ADFS spec says not to specify a locality
		SAMLStatement[] statements = {new SAMLAuthenticationStatement(subject, authenticationMethod, authTime, null,
				null, null)};

		// Package attributes
		log.info("Resolving attributes.");

		SAMLAssertion assertion = new SAMLAssertion(issuer, new Date(System.currentTimeMillis()), new Date(System
				.currentTimeMillis() + 300000), conditions, null, Arrays.asList(statements));

		if (log.isDebugEnabled()) {
			log.debug("Dumping generated Assertion:" + System.getProperty("line.separator") + assertion.toString());
		}

		return assertion;
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#getHandlerName()
	 */
	public String getHandlerName() {

		return "ADFS SSO Handler";
	}

	private void validateAdfsSpecificData(HttpServletRequest request) throws InvalidClientDataException {

		// Required by spec, must have the constant value
		if (request.getParameter("wa") == null || !request.getParameter("wa").equals(ADFS_SSOHandler.WA)) { throw new InvalidClientDataException(
				"Invalid data from Service Provider: missing or invalid (wa) parameter."); }

		// Required by spec
		if ((request.getParameter("wtrealm") == null) || (request.getParameter("wtrealm").equals(""))) { throw new InvalidClientDataException(
				"Invalid data from Service Provider:missing or invalid (wtrealm) parameter."); }
	}

	private static void createPOSTForm(HttpServletRequest req, HttpServletResponse res,
			SecurityTokenResponse tokenResponse) throws IOException, ServletException, SecurityTokenResponseException {

		req.setAttribute("wresult", tokenResponse.toXmlString());

		if (log.isDebugEnabled()) {
			log.debug("Dumping generated Security Token Response:" + System.getProperty("line.separator")
					+ tokenResponse.toXmlString());
		}

		RequestDispatcher rd = req.getRequestDispatcher("/adfs.jsp");
		rd.forward(req, res);
	}

	/**
	 * Boolean indication of whethere or not a given assertion consumer URL is valid for a given SP.
	 */
	private static boolean isValidAssertionConsumerURL(SPSSODescriptor descriptor, String shireURL)
			throws InvalidClientDataException {

		List<AssertionConsumerService> endpoints = descriptor.getAssertionConsumerServices();
		for (AssertionConsumerService acs : endpoints) {
			if (shireURL.equals(acs.getLocation())) { return true; }
		}

		log.info("Supplied consumer URL not found in metadata.");
		return false;
	}

}

class SecurityTokenResponse {

	private static Logger log = Logger.getLogger(SecurityTokenResponse.class.getName());
	private static SAMLConfig config = SAMLConfig.instance();
	private static String WS_TRUST_SCHEMA = "http://schemas.xmlsoap.org/ws/2005/02/trust";
	private static String WS_POLICY_SCHEMA = "http://schemas.xmlsoap.org/ws/2004/09/policy";
	private static String WS_ADDRESSING_SCHEMA = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
	private Document response;

	SecurityTokenResponse(SAMLAssertion assertion, String remoteProviderId) throws SecurityTokenResponseException,
			SAMLException {

		response = XML.parserPool.newDocument();

		// Create root response element
		Element root = response.createElementNS(WS_TRUST_SCHEMA, "RequestSecurityTokenResponse");
		root.setAttributeNS(XML.XMLNS_NS, "xmlns", WS_TRUST_SCHEMA);
		response.appendChild(root);

		// Tie to remote endpoint
		Element appliesTo = response.createElementNS(WS_POLICY_SCHEMA, "AppliesTo");
		appliesTo.setAttributeNS(XML.XMLNS_NS, "xmlns", WS_POLICY_SCHEMA);
		root.appendChild(appliesTo);
		Element endpointRef = response.createElementNS(WS_ADDRESSING_SCHEMA, "EndpointReference");
		endpointRef.setAttributeNS(XML.XMLNS_NS, "xmlns", WS_ADDRESSING_SCHEMA);
		appliesTo.appendChild(endpointRef);
		Element address = response.createElementNS(WS_ADDRESSING_SCHEMA, "Address");
		address.appendChild(response.createTextNode(remoteProviderId));
		endpointRef.appendChild(address);

		// Add security token
		Element token = response.createElementNS(WS_TRUST_SCHEMA, "RequestedSecurityToken");

		token.appendChild(assertion.toDOM(response));
		root.appendChild(token);

	}

	public byte[] toBase64() throws SecurityTokenResponseException {

		try {
			Canonicalizer canonicalizier = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			byte[] canonicalized = canonicalizier.canonicalizeSubtree(response, config
					.getProperty("org.opensaml.inclusive-namespace-prefixes"));

			return Base64.encodeBase64Chunked(canonicalized);
		} catch (InvalidCanonicalizerException e) {
			log.error("Error Canonicalizing Security Token Response: " + e);
			throw new SecurityTokenResponseException(e.getMessage());
		}

		catch (CanonicalizationException e) {
			log.error("Error Canonicalizing Security Token Response: " + e);
			throw new SecurityTokenResponseException(e.getMessage());
		}
	}

	public String toXmlString() throws SecurityTokenResponseException {

		try {
			Canonicalizer canonicalizier = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			byte[] canonicalized = canonicalizier.canonicalizeSubtree(response, config
					.getProperty("org.opensaml.inclusive-namespace-prefixes"));
			return new String(canonicalized);

		} catch (InvalidCanonicalizerException e) {
			log.error("Error Canonicalizing Security Token Response: " + e);
			throw new SecurityTokenResponseException(e.getMessage());
		}

		catch (CanonicalizationException e) {
			log.error("Error Canonicalizing Security Token Response: " + e);
			throw new SecurityTokenResponseException(e.getMessage());
		}
	}

}

class SecurityTokenResponseException extends Exception {

	SecurityTokenResponseException(String message) {

		super(message);
	}
}