/*
 * Created on Mar 10, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
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

import sun.misc.BASE64Decoder;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.InvalidClientDataException;

import edu.internet2.middleware.shibboleth.metadata.Endpoint;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.SPSSODescriptor;


/**
 * @author Walter Hoehn
 */
public class ShibbolethV1SSOHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(ShibbolethV1SSOHandler.class.getName());

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#validForRequest(javax.servlet.http.HttpServletRequest)
	 */
	// TODO move this into the process method
	boolean validForRequest(HttpServletRequest request) {

		if (request.getParameter("target") != null && !request.getParameter("target").equals("")
				&& request.getParameter("shire") != null && !request.getParameter("shire").equals("")) {
			log.debug("Found (target) and (shire) parameters.  Request "
					+ "appears to be valid for the Shibboleth v1 profile.");
			return true;
		} else {
			return false;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws InvalidClientDataException, SAMLException,
			ServletException, IOException {

		// TODO make sure the saml request is null for now

		// Ensure that we have the required data from the servlet container
		IdPProtocolSupport.validateEngineData(request);

		// Get the authN info
		String username = support.getIdPConfig().getAuthHeaderName().equalsIgnoreCase("REMOTE_USER") ? request
				.getRemoteUser() : request.getHeader(support.getIdPConfig().getAuthHeaderName());

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
			log.debug("User was authenticated via the default method for this relying party (" + authenticationMethod
					+ ").");
		} else {
			log.debug("User was authenticated via the method (" + authenticationMethod + ").");
		}

		// TODO change name!!!
		// TODO We might someday want to provide a mechanism for the authenticator to specify the auth time
		SAMLAssertion[] assertions = foo(request, relyingParty, provider, nameId, authenticationMethod, new Date(System
				.currentTimeMillis()));

		// TODO do assertion signing for artifact stuff

		// SAML Artifact profile
		if (useArtifactProfile(provider, acceptanceURL)) {
			log.debug("Responding with Artifact profile.");

			// Create artifacts for each assertion
			ArrayList artifacts = new ArrayList();
			for (int i = 0; i < assertions.length; i++) {
				// TODO replace the artifact stuff here!!!
				// artifacts.add(artifactMapper.generateArtifact(assertions[i], relyingParty));
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
							+ username + "). Name Identifier: (" + nameId.getName() + "). Name Identifier Format: ("
							+ nameId.getFormat() + ").");

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
						"Authentication assertion issued to legacy provider (SHIRE: " + request.getParameter("shire")
								+ ") on behalf of principal (" + username + ") for resource ("
								+ request.getParameter("target") + "). Name Identifier: (" + nameId.getName()
								+ "). Name Identifier Format: (" + nameId.getFormat() + ").");
			} else {
				support.getTransactionLog().info(
						"Authentication assertion issued to provider ("
								+ relyingParty.getIdentityProvider().getProviderId() + ") on behalf of principal ("
								+ username + "). Name Identifier: (" + nameId.getName()
								+ "). Name Identifier Format: (" + nameId.getFormat() + ").");
			}
		}
		return null;
	}

	SAMLAssertion[] foo(HttpServletRequest request, RelyingParty relyingParty, EntityDescriptor provider,
			SAMLNameIdentifier nameId, String authenticationMethod, Date authTime) throws SAMLException, IOException {

		Document doc = org.opensaml.XML.parserPool.newDocument();

		// Determine audiences and issuer
		ArrayList audiences = new ArrayList();
		if (relyingParty.getProviderId() != null) {
			audiences.add(relyingParty.getProviderId());
		}
		if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
			audiences.add(relyingParty.getName());
		}

		String issuer = null;
		if (relyingParty.isLegacyProvider()) {
			// TODO figure this out
			/*
			 * log.debug("Service Provider is running Shibboleth <= 1.1. Using old style issuer."); if
			 * (relyingParty.getIdentityProvider().getResponseSigningCredential() == null ||
			 * relyingParty.getIdentityProvider().getResponseSigningCredential().getX509Certificate() == null) { throw
			 * new SAMLException( "Cannot serve legacy style assertions without an X509 certificate"); } issuer =
			 * ShibBrowserProfile.getHostNameFromDN(relyingParty.getIdentityProvider()
			 * .getResponseSigningCredential().getX509Certificate().getSubjectX500Principal()); if (issuer == null ||
			 * issuer.equals("")) { throw new SAMLException( "Error parsing certificate DN while determining legacy
			 * issuer name."); }
			 */
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

		// TODO: This will actually favor artifact, since a given location could support
		// both profiles. If that's not what we want, needs adjustment...
		Iterator endpoints = sp.getAssertionConsumerServiceManager().getEndpoints();
		while (endpoints.hasNext()) {
			Endpoint ep = (Endpoint) endpoints.next();
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
