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

package edu.internet2.middleware.shibboleth.idp;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.InvalidCryptoException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeDesignator;
import org.opensaml.SAMLAttributeQuery;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLAuthorityBinding;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBindingFactory;
import org.opensaml.SAMLBrowserProfile;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.opensaml.artifact.Artifact;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;
import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpProcessingException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolverException;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.OriginConfig;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibBrowserProfile;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.metadata.Endpoint;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.metadata.SPSSODescriptor;

/**
 * Primary entry point for requests to the SAML IdP. Listens on multiple endpoints, routes requests to the appropriate
 * IdP processing components, and delivers proper protocol responses.
 * 
 * @author Walter Hoehn
 */

public class IdPResponder extends HttpServlet {

	private static Logger transactionLog = Logger.getLogger("Shibboleth-TRANSACTION");
	private static Logger log = Logger.getLogger(IdPResponder.class.getName());
	private static Random idgen = new Random();
	private SAMLBinding binding;
	private Semaphore throttle;
	private IdPConfig configuration;
	private ProtocolHandler[] protocolHandlers;
	private ProtocolSupport protocolSupport;

	public void init() throws ServletException {

		super.init();
		MDC.put("serviceId", "[IdP] Core");
		log.info("Initializing Identity Provider.");

		try {
			binding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);

			Document originConfig = OriginConfig.getOriginConfig(this.getServletContext());

			// Load global configuration properties
			configuration = new IdPConfig(originConfig.getDocumentElement());

			// Load a semaphore that throttles how many requests the IdP will handle at once
			throttle = new Semaphore(configuration.getMaxThreads());

			// Load name mappings
			NameMapper nameMapper = new NameMapper();
			NodeList itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(
					NameIdentifierMapping.mappingNamespace, "NameMapping");

			for (int i = 0; i < itemElements.getLength(); i++) {
				try {
					nameMapper.addNameMapping((Element) itemElements.item(i));
				} catch (NameIdentifierMappingException e) {
					log.error("Name Identifier mapping could not be loaded: " + e);
				}
			}

			// Load signing credentials
			itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(Credentials.credentialsNamespace,
					"Credentials");
			if (itemElements.getLength() < 1) {
				log.error("No credentials specified.");
			}
			if (itemElements.getLength() > 1) {
				log.error("Multiple Credentials specifications found, using first.");
			}
			Credentials credentials = new Credentials((Element) itemElements.item(0));

			// Load relying party config
			ServiceProviderMapper spMapper;
			try {
				spMapper = new ServiceProviderMapper(originConfig.getDocumentElement(), configuration, credentials,
						nameMapper);
			} catch (ServiceProviderMapperException e) {
				log.error("Could not load Identity Provider configuration: " + e);
				throw new ShibbolethConfigurationException("Could not load Identity Provider configuration.");
			}

			// Startup Attribute Resolver & ARP engine
			AttributeResolver resolver = null;
			ArpEngine arpEngine = null;
			try {
				resolver = new AttributeResolver(configuration);

				itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(
						IdPConfig.originConfigNamespace, "ReleasePolicyEngine");

				if (itemElements.getLength() > 1) {
					log.warn("Encountered multiple <ReleasePolicyEngine> configuration elements.  Using first...");
				}
				if (itemElements.getLength() < 1) {
					arpEngine = new ArpEngine();
				} else {
					arpEngine = new ArpEngine((Element) itemElements.item(0));
				}

			} catch (ArpException ae) {
				log.fatal("The Identity Provider could not be initialized "
						+ "due to a problem with the ARP Engine configuration: " + ae);
				throw new ShibbolethConfigurationException("Could not load ARP Engine.");
			} catch (AttributeResolverException ne) {
				log.fatal("The Identity Provider could not be initialized due "
						+ "to a problem with the Attribute Resolver configuration: " + ne);
				throw new ShibbolethConfigurationException("Could not load Attribute Resolver.");
			}

			// Load protocol handlers and support library
			protocolSupport = new ProtocolSupport(configuration, transactionLog, nameMapper, spMapper, arpEngine,
					resolver);
			log.debug("Starting with Shibboleth v1 protocol handling enabled.");
			protocolHandlers = new ProtocolHandler[]{new Shibbolethv1SSOHandler()};

			// Load metadata
			itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.originConfigNamespace,
					"FederationProvider");
			for (int i = 0; i < itemElements.getLength(); i++) {
				protocolSupport.addFederationProvider((Element) itemElements.item(i));
			}
			if (protocolSupport.providerCount() < 1) {
				log.error("No Federation Provider metadata loaded.");
				throw new ShibbolethConfigurationException("Could not load federation metadata.");
			}

			log.info("Identity Provider initialization complete.");

		} catch (ShibbolethConfigurationException ae) {
			log.fatal("The Identity Provider could not be initialized: " + ae);
			throw new UnavailableException("Identity Provider failed to initialize.");
		} catch (SAMLException se) {
			log.fatal("SAML SOAP binding could not be loaded: " + se);
			throw new UnavailableException("Identity Provider failed to initialize.");
		}
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MDC.put("serviceId", "[IdP] " + idgen.nextInt());
		MDC.put("remoteAddr", request.getRemoteAddr());
		log.debug("Recieved a request via GET.");

		try {
			// TODO this throttle should probably just wrap signing operations...
			throttle.enter();

			// Determine which protocol we are responding to (at this point, Shibv1 vs. EAuth)
			ProtocolHandler activeHandler = null;
			for (int i = 0; i < protocolHandlers.length; i++) {
				if (protocolHandlers[i].validForRequest(request)) {
					activeHandler = protocolHandlers[i];
					break;
				}
			}

			if (activeHandler == null) { throw new InvalidClientDataException(
					"The request did not contain sufficient parameter data to determine the protocol."); }

			log.info("Processing " + activeHandler.getHandlerName() + " request.");
			// Pass request to the appropriate handler
			activeHandler.processRequest(request, response, protocolSupport);

		} catch (NameIdentifierMappingException ex) {
			log.error(ex);
			handleSSOError(request, response, ex);
			return;
		} catch (InvalidClientDataException ex) {
			log.error(ex);
			handleSSOError(request, response, ex);
			return;
		} catch (SAMLException ex) {
			log.error(ex);
			handleSSOError(request, response, ex);
			return;
		} catch (InterruptedException ex) {
			log.error(ex);
			handleSSOError(request, response, ex);
			return;
		} finally {
			throttle.exit();
		}
	}

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MDC.put("serviceId", "[IdP] " + idgen.nextInt());
		MDC.put("remoteAddr", request.getRemoteAddr());
		log.debug("Recieved a request via POST.");

		// Determine which protocol we are responding to (at this point, Shibv1 vs. EAuth)
		ProtocolHandler activeHandler = null;
		for (int i = 0; i < protocolHandlers.length; i++) {
			if (protocolHandlers[i].validForRequest(request)) {
				activeHandler = protocolHandlers[i];
				break;
			}
		}

		// TODO some other type of error here
		/*
		 * if (activeHandler == null) { throw new InvalidClientDataException( "The request did not contain sufficient
		 * parameter data to determine the protocol."); }
		 */
		log.info("Processing " + activeHandler.getHandlerName() + " request.");
		// Pass request to the appropriate handler
	//	activeHandler.processRequest(request, response, protocolSupport);

		// Parse SOAP request and marshall SAML request object
		SAMLRequest samlRequest = null;
		try {
			try {
				samlRequest = binding.receive(request);
			} catch (SAMLException e) {
				log.fatal("Unable to parse request: " + e);
				throw new SAMLException("Invalid request data.");
			}

			// If we have DEBUGing turned on, dump out the request to the log
			// This takes some processing, so only do it if we need to
			if (log.isDebugEnabled()) {
				try {
					log.debug("Dumping generated SAML Request:"
							+ System.getProperty("line.separator")
							+ new String(new BASE64Decoder().decodeBuffer(new String(samlRequest.toBase64(), "ASCII")),
									"UTF8"));
				} catch (SAMLException e) {
					log.error("Encountered an error while decoding SAMLRequest for logging purposes.");
				} catch (IOException e) {
					log.error("Encountered an error while decoding SAMLRequest for logging purposes.");
				}
			}

			// Determine the request type
			Iterator artifacts = samlRequest.getArtifacts();
			if (artifacts.hasNext()) {
				artifacts = null; // get rid of the iterator
				log.info("Recieved a request to dereference an assertion artifact.");

				// processArtifactDereference(samlRequest, request, response);
				return;
			}

			if (samlRequest.getQuery() != null && (samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
				log.info("Recieved an attribute query.");
				processAttributeQuery(samlRequest, request, response);
				return;
			}

			throw new SAMLException(SAMLException.REQUESTER,
					"Identity Provider unable to respond to this SAML Request type.");

		} catch (InvalidNameIdentifierException invalidNameE) {
			log.info("Could not associate the request subject with a principal: " + invalidNameE);
			try {
				// TODO once again, ifgure out passThruErrors
				if (false) {
					// if (relyingParty.passThruErrors()) {
					sendSAMLFailureResponse(response, samlRequest, new SAMLException(Arrays.asList(invalidNameE
							.getSAMLErrorCodes()), "The supplied Subject was unrecognized.", invalidNameE));

				} else {
					sendSAMLFailureResponse(response, samlRequest, new SAMLException(Arrays.asList(invalidNameE
							.getSAMLErrorCodes()), "The supplied Subject was unrecognized."));
				}
				return;
			} catch (Exception ee) {
				log.fatal("Could not construct a SAML error response: " + ee);
				throw new ServletException("Identity Provider response failure.");
			}
		} catch (Exception e) {
			log.error("Error while processing request: " + e);
			try {
				// TODO figure out how to implement the passThru error handling
				// below
				// if (relyingParty != null && relyingParty.passThruErrors()) {
				if (false) {
					sendSAMLFailureResponse(response, samlRequest, new SAMLException(SAMLException.RESPONDER,
							"General error processing request.", e));
				} else if (configuration.passThruErrors()) {
					sendSAMLFailureResponse(response, samlRequest, new SAMLException(SAMLException.RESPONDER,
							"General error processing request.", e));
				} else {
					sendSAMLFailureResponse(response, samlRequest, new SAMLException(SAMLException.RESPONDER,
							"General error processing request."));
				}
				return;
			} catch (Exception ee) {
				log.fatal("Could not construct a SAML error response: " + ee);
				throw new ServletException("Identity Provider response failure.");
			}
		}
	}

	// TODO this should be renamed, since it is now only one type of response
	// that we can send
	public void sendSAMLResponse(HttpServletResponse resp, SAMLAttribute[] attrs, SAMLRequest samlRequest,
			RelyingParty relyingParty, SAMLException exception) throws IOException {

		SAMLException ourSE = null;
		SAMLResponse samlResponse = null;

		try {
			if (attrs == null || attrs.length == 0) {
				// No attribute found
				samlResponse = new SAMLResponse(samlRequest.getId(), null, null, exception);
			} else {

				SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

				// Reference requested subject
				SAMLSubject rSubject = (SAMLSubject) attributeQuery.getSubject().clone();

				// Set appropriate audience
				ArrayList audiences = new ArrayList();
				if (relyingParty.getProviderId() != null) {
					audiences.add(relyingParty.getProviderId());
				}
				if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
					audiences.add(relyingParty.getName());
				}
				SAMLCondition condition = new SAMLAudienceRestrictionCondition(audiences);

				// Put all attributes into an assertion
				SAMLStatement statement = new SAMLAttributeStatement(rSubject, Arrays.asList(attrs));

				// Set assertion expiration to longest attribute expiration
				long max = 0;
				for (int i = 0; i < attrs.length; i++) {
					if (max < attrs[i].getLifetime()) {
						max = attrs[i].getLifetime();
					}
				}
				Date now = new Date();
				Date then = new Date(now.getTime() + (max * 1000)); // max is in
				// seconds

				SAMLAssertion sAssertion = new SAMLAssertion(relyingParty.getIdentityProvider().getProviderId(), now,
						then, Collections.singleton(condition), null, Collections.singleton(statement));

				samlResponse = new SAMLResponse(samlRequest.getId(), null, Collections.singleton(sAssertion), exception);
				ProtocolSupport.addSignatures(samlResponse, relyingParty, protocolSupport.lookup(relyingParty
						.getProviderId()), false);
			}
		} catch (SAMLException se) {
			ourSE = se;
		} catch (CloneNotSupportedException ex) {
			ourSE = new SAMLException(SAMLException.RESPONDER, ex);

		} finally {

			if (log.isDebugEnabled()) { // This takes some processing, so only do it if we need to
				try {
					log.debug("Dumping generated SAML Response:"
							+ System.getProperty("line.separator")
							+ new String(
									new BASE64Decoder().decodeBuffer(new String(samlResponse.toBase64(), "ASCII")),
									"UTF8"));
				} catch (SAMLException e) {
					log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
				} catch (IOException e) {
					log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
				}
			}

			try {
				binding.respond(resp, samlResponse, ourSE);
			} catch (SAMLException e) {
				log.error("Caught exception while responding to requester: " + e.getMessage());
				resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error while responding.");
			}
		}
	}

	// TODO get rid of this AAException thing
	private void processAttributeQuery(SAMLRequest samlRequest, HttpServletRequest request, HttpServletResponse response)
			throws SAMLException, IOException, ServletException, AAException, InvalidNameIdentifierException,
			NameIdentifierMappingException {

		// TODO validate that the endpoint is valid for the request type

		RelyingParty relyingParty = null;

		SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

		if (!fromLegacyProvider(request)) {
			log.info("Remote provider has identified itself as: (" + attributeQuery.getResource() + ").");
		}

		// This is the requester name that will be passed to subsystems
		String effectiveName = null;

		X509Certificate credential = getCredentialFromProvider(request);
		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request is from an unauthenticated service provider.");
		} else {

			// Identify a Relying Party
			relyingParty = protocolSupport.getServiceProviderMapper().getRelyingParty(attributeQuery.getResource());

			try {
				effectiveName = getEffectiveName(request, relyingParty);
			} catch (InvalidProviderCredentialException ipc) {
				sendSAMLFailureResponse(response, samlRequest, new SAMLException(SAMLException.RESPONDER,
						"Invalid credentials for request."));
				return;
			}
		}

		if (effectiveName == null) {
			log.debug("Using default Relying Party for unauthenticated provider.");
			relyingParty = protocolSupport.getServiceProviderMapper().getRelyingParty(null);
		}

		// Fail if we can't honor SAML Subject Confirmation
		if (!fromLegacyProvider(request)) {
			Iterator iterator = attributeQuery.getSubject().getConfirmationMethods();
			boolean hasConfirmationMethod = false;
			while (iterator.hasNext()) {
				log.info("Request contains SAML Subject Confirmation method: (" + (String) iterator.next() + ").");
			}
			if (hasConfirmationMethod) { throw new SAMLException(SAMLException.REQUESTER,
					"This SAML authority cannot honor requests containing the supplied SAML Subject Confirmation Method."); }
		}

		// Map Subject to local principal
		Principal principal = protocolSupport.getNameMapper().getPrincipal(attributeQuery.getSubject().getName(),
				relyingParty, relyingParty.getIdentityProvider());
		log.info("Request is for principal (" + principal.getName() + ").");

		SAMLAttribute[] attrs;
		Iterator requestedAttrsIterator = attributeQuery.getDesignators();
		if (requestedAttrsIterator.hasNext()) {
			log.info("Request designates specific attributes, resolving this set.");
			ArrayList requestedAttrs = new ArrayList();
			while (requestedAttrsIterator.hasNext()) {
				SAMLAttributeDesignator attribute = (SAMLAttributeDesignator) requestedAttrsIterator.next();
				try {
					log.debug("Designated attribute: (" + attribute.getName() + ")");
					requestedAttrs.add(new URI(attribute.getName()));
				} catch (URISyntaxException use) {
					log.error("Request designated an attribute name that does not conform to the required URI syntax ("
							+ attribute.getName() + ").  Ignoring this attribute");
				}
			}

			attrs = protocolSupport.getReleaseAttributes(principal, effectiveName, null, (URI[]) requestedAttrs
					.toArray(new URI[0]));
		} else {
			log.info("Request does not designate specific attributes, resolving all available.");
			attrs = protocolSupport.getReleaseAttributes(principal, effectiveName, null);
		}

		log.info("Found " + attrs.length + " attribute(s) for " + principal.getName());
		sendSAMLResponse(response, attrs, samlRequest, relyingParty, null);
		log.info("Successfully responded about " + principal.getName());

		if (effectiveName == null) {
			if (fromLegacyProvider(request)) {
				transactionLog.info("Attribute assertion issued to anonymous legacy provider at ("
						+ request.getRemoteAddr() + ") on behalf of principal (" + principal.getName() + ").");
			} else {
				transactionLog.info("Attribute assertion issued to anonymous provider at (" + request.getRemoteAddr()
						+ ") on behalf of principal (" + principal.getName() + ").");
			}
		} else {
			if (fromLegacyProvider(request)) {
				transactionLog.info("Attribute assertion issued to legacy provider (" + effectiveName
						+ ") on behalf of principal (" + principal.getName() + ").");
			} else {
				transactionLog.info("Attribute assertion issued to provider (" + effectiveName
						+ ") on behalf of principal (" + principal.getName() + ").");
			}
		}

	}

	/*
	 * private void processArtifactDereference(SAMLRequest samlRequest, HttpServletRequest request, HttpServletResponse
	 * response) throws SAMLException, IOException { // TODO validate that the endpoint is valid for the request type //
	 * TODO how about signatures on artifact dereferencing // Pull credential from request X509Certificate credential =
	 * getCredentialFromProvider(request); if (credential == null ||
	 * credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) { // The spec says that mutual
	 * authentication is required for the // artifact profile log.info("Request is from an unauthenticated service
	 * provider."); throw new SAMLException(SAMLException.REQUESTER, "SAML Artifacts cannot be dereferenced for
	 * unauthenticated requesters."); } log.info("Request contains credential: (" +
	 * credential.getSubjectX500Principal().getName(X500Principal.RFC2253) + ")."); ArrayList assertions = new
	 * ArrayList(); Iterator artifacts = samlRequest.getArtifacts(); int queriedArtifacts = 0; StringBuffer
	 * dereferencedArtifacts = new StringBuffer(); // for // transaction // log while (artifacts.hasNext()) {
	 * queriedArtifacts++; String artifact = (String) artifacts.next(); log.debug("Attempting to dereference artifact: (" +
	 * artifact + ")."); ArtifactMapping mapping = artifactMapper.recoverAssertion(artifact); if (mapping != null) {
	 * SAMLAssertion assertion = mapping.getAssertion(); // See if we have metadata for this provider EntityDescriptor
	 * provider = lookup(mapping.getServiceProviderId()); if (provider == null) { log.info("No metadata found for
	 * provider: (" + mapping.getServiceProviderId() + ")."); throw new SAMLException(SAMLException.REQUESTER, "Invalid
	 * service provider."); } // Make sure that the suppplied credential is valid for the // provider to which the
	 * artifact was issued if (!isValidCredential(provider, credential)) { log.error("Supplied credential (" +
	 * credential.getSubjectX500Principal().getName(X500Principal.RFC2253) + ") is NOT valid for provider (" +
	 * mapping.getServiceProviderId() + "), to whom this artifact was issued."); throw new
	 * SAMLException(SAMLException.REQUESTER, "Invalid credential."); } log.debug("Supplied credential validated for the
	 * provider to which this artifact was issued."); assertions.add(assertion); dereferencedArtifacts.append("(" +
	 * artifact + ")"); } } // The spec requires that if any artifacts are dereferenced, they must // all be
	 * dereferenced if (assertions.size() > 0 && assertions.size() != queriedArtifacts) { throw new SAMLException(
	 * SAMLException.REQUESTER, "Unable to successfully dereference all artifacts."); } // Create and send response //
	 * The spec says that we should send "success" in the case where no // artifacts match SAMLResponse samlResponse =
	 * new SAMLResponse(samlRequest.getId(), null, assertions, null); if (log.isDebugEnabled()) { try {
	 * log.debug("Dumping generated SAML Response:" + System.getProperty("line.separator") + new String(new
	 * BASE64Decoder().decodeBuffer(new String(samlResponse.toBase64(), "ASCII")), "UTF8")); } catch (SAMLException e) {
	 * log.error("Encountered an error while decoding SAMLReponse for logging purposes."); } catch (IOException e) {
	 * log.error("Encountered an error while decoding SAMLReponse for logging purposes."); } } binding.respond(response,
	 * samlResponse, null); transactionLog.info("Succesfully dereferenced the following artifacts: " +
	 * dereferencedArtifacts.toString()); }
	 */

	private void sendSAMLFailureResponse(HttpServletResponse httpResponse, SAMLRequest samlRequest,
			SAMLException exception) throws IOException {

		try {
			SAMLResponse samlResponse = new SAMLResponse((samlRequest != null) ? samlRequest.getId() : null, null,
					null, exception);
			if (log.isDebugEnabled()) {
				try {
					log.debug("Dumping generated SAML Error Response:"
							+ System.getProperty("line.separator")
							+ new String(
									new BASE64Decoder().decodeBuffer(new String(samlResponse.toBase64(), "ASCII")),
									"UTF8"));
				} catch (IOException e) {
					log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
				}
			}
			binding.respond(httpResponse, samlResponse, null);
			log.debug("Returning SAML Error Response.");
		} catch (SAMLException se) {
			try {
				binding.respond(httpResponse, null, exception);
			} catch (SAMLException e) {
				log.error("Caught exception while responding to requester: " + e.getMessage());
				httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error while responding.");
			}
			log.error("Identity Provider failed to make an error message: " + se);
		}
	}

	private String getEffectiveName(HttpServletRequest req, RelyingParty relyingParty)
			throws InvalidProviderCredentialException {

		// X500Principal credentialName = getCredentialName(req);
		X509Certificate credential = getCredentialFromProvider(req);

		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request is from an unauthenticated service provider.");
			return null;

		} else {
			log.info("Request contains credential: ("
					+ credential.getSubjectX500Principal().getName(X500Principal.RFC2253) + ").");
			// Mockup old requester name for requests from < 1.2 targets
			if (fromLegacyProvider(req)) {
				String legacyName = ShibBrowserProfile.getHostNameFromDN(credential.getSubjectX500Principal());
				if (legacyName == null) {
					log.error("Unable to extract legacy requester name from certificate subject.");
				}

				log.info("Request from legacy service provider: (" + legacyName + ").");
				return legacyName;

			} else {

				// See if we have metadata for this provider
				EntityDescriptor provider = protocolSupport.lookup(relyingParty.getProviderId());
				if (provider == null) {
					log.info("No metadata found for provider: (" + relyingParty.getProviderId() + ").");
					log.info("Treating remote provider as unauthenticated.");
					return null;
				}

				// Make sure that the suppplied credential is valid for the
				// selected relying party
				if (isValidCredential(provider, credential)) {
					log.info("Supplied credential validated for this provider.");
					log.info("Request from service provider: (" + relyingParty.getProviderId() + ").");
					return relyingParty.getProviderId();
				} else {
					log.error("Supplied credential ("
							+ credential.getSubjectX500Principal().getName(X500Principal.RFC2253)
							+ ") is NOT valid for provider (" + relyingParty.getProviderId() + ").");
					throw new InvalidProviderCredentialException("Invalid credential.");
				}
			}
		}
	}

	private static X509Certificate getCredentialFromProvider(HttpServletRequest req) {

		X509Certificate[] certArray = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
		if (certArray != null && certArray.length > 0) { return certArray[0]; }
		return null;
	}

	private static boolean isValidCredential(EntityDescriptor provider, X509Certificate certificate) {

		SPSSODescriptor sp = provider.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
		if (sp == null) {
			log.info("Inappropriate metadata for provider.");
			return false;
		}
		// TODO figure out what to do about this role business here
		Iterator descriptors = sp.getKeyDescriptors();
		while (descriptors.hasNext()) {
			KeyInfo keyInfo = ((KeyDescriptor) descriptors.next()).getKeyInfo();
			for (int l = 0; keyInfo.lengthKeyName() > l; l++) {
				try {

					// First, try to match DN against metadata
					try {
						if (certificate.getSubjectX500Principal().getName(X500Principal.RFC2253).equals(
								new X500Principal(keyInfo.itemKeyName(l).getKeyName()).getName(X500Principal.RFC2253))) {
							log.debug("Matched against DN.");
							return true;
						}
					} catch (IllegalArgumentException iae) {
						// squelch this runtime exception, since
						// this might be a valid case
					}

					// If that doesn't work, we try matching against
					// some Subject Alt Names
					try {
						Collection altNames = certificate.getSubjectAlternativeNames();
						if (altNames != null) {
							for (Iterator nameIterator = altNames.iterator(); nameIterator.hasNext();) {
								List altName = (List) nameIterator.next();
								if (altName.get(0).equals(new Integer(2)) || altName.get(0).equals(new Integer(6))) { // 2 is
									// DNS,
									// 6 is
									// URI
									if (altName.get(1).equals(keyInfo.itemKeyName(l).getKeyName())) {
										log.debug("Matched against SubjectAltName.");
										return true;
									}
								}
							}
						}
					} catch (CertificateParsingException e1) {
						log
								.error("Encountered an problem trying to extract Subject Alternate Name from supplied certificate: "
										+ e1);
					}

					// If that doesn't work, try to match using
					// SSL-style hostname matching
					if (ShibBrowserProfile.getHostNameFromDN(certificate.getSubjectX500Principal()).equals(
							keyInfo.itemKeyName(l).getKeyName())) {
						log.debug("Matched against hostname.");
						return true;
					}

				} catch (XMLSecurityException e) {
					log.error("Encountered an error reading federation metadata: " + e);
				}
			}
		}
		log.info("Supplied credential not found in metadata.");
		return false;
	}

	private static boolean fromLegacyProvider(HttpServletRequest request) {

		String version = request.getHeader("Shibboleth");
		if (version != null) {
			log.debug("Request from Shibboleth version: " + version);
			return false;
		}
		log.debug("No version header found.");
		return true;
	}

	// TODO this should be renamed
	private static void handleSSOError(HttpServletRequest req, HttpServletResponse res, Exception e)
			throws ServletException, IOException {

		req.setAttribute("errorText", e.toString());
		req.setAttribute("requestURL", req.getRequestURI().toString());
		RequestDispatcher rd = req.getRequestDispatcher("/hserror.jsp");
		// TODO rename hserror.jsp to a more appropriate name
		rd.forward(req, res);
	}

	private class Semaphore {

		private int value;

		public Semaphore(int value) {

			this.value = value;
		}

		public synchronized void enter() throws InterruptedException {

			--value;
			if (value < 0) {
				wait();
			}
		}

		public synchronized void exit() {

			++value;
			notify();
		}
	}

	private class InvalidProviderCredentialException extends Exception {

		public InvalidProviderCredentialException(String message) {

			super(message);
		}
	}

}

class InvalidClientDataException extends Exception {

	public InvalidClientDataException(String message) {

		super(message);
	}

}

class ProtocolSupport implements Metadata {

	private static Logger log = Logger.getLogger(ProtocolSupport.class.getName());
	private Logger transactionLog;
	private IdPConfig config;
	private ArrayList fedMetadata = new ArrayList();
	private NameMapper nameMapper;
	private ServiceProviderMapper spMapper;
	private ArpEngine arpEngine;
	private AttributeResolver resolver;

	ProtocolSupport(IdPConfig config, Logger transactionLog, NameMapper nameMapper, ServiceProviderMapper spMapper,
			ArpEngine arpEngine, AttributeResolver resolver) {

		this.transactionLog = transactionLog;
		this.config = config;
		this.nameMapper = nameMapper;
		this.spMapper = spMapper;
		spMapper.setMetadata(this);
		this.arpEngine = arpEngine;
		this.resolver = resolver;
	}

	public static void validateEngineData(HttpServletRequest req) throws InvalidClientDataException {

		if ((req.getRemoteUser() == null) || (req.getRemoteUser().equals(""))) { throw new InvalidClientDataException(
				"Unable to authenticate remote user"); }
		if ((req.getRemoteAddr() == null) || (req.getRemoteAddr().equals(""))) { throw new InvalidClientDataException(
				"Unable to obtain client address."); }
	}

	public Logger getTransactionLog() {

		return transactionLog;
	}

	public IdPConfig getIdPConfig() {

		return config;
	}

	public NameMapper getNameMapper() {

		return nameMapper;
	}

	public ServiceProviderMapper getServiceProviderMapper() {

		return spMapper;
	}

	public static void addSignatures(SAMLResponse response, RelyingParty relyingParty, EntityDescriptor provider,
			boolean signResponse) throws SAMLException {

		if (provider != null) {
			boolean signAssertions = false;

			SPSSODescriptor sp = provider.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
			if (sp == null) {
				log.info("Inappropriate metadata for provider: " + provider.getId() + ".  Expected SPSSODescriptor.");
			}
			if (sp.getWantAssertionsSigned()) {
				signAssertions = true;
			}

			if (signAssertions && relyingParty.getIdentityProvider().getSigningCredential() != null
					&& relyingParty.getIdentityProvider().getSigningCredential().getPrivateKey() != null) {

				Iterator assertions = response.getAssertions();

				while (assertions.hasNext()) {
					SAMLAssertion assertion = (SAMLAssertion) assertions.next();
					String assertionAlgorithm;
					if (relyingParty.getIdentityProvider().getSigningCredential().getCredentialType() == Credential.RSA) {
						assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
					} else if (relyingParty.getIdentityProvider().getSigningCredential().getCredentialType() == Credential.DSA) {
						assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
					} else {
						throw new InvalidCryptoException(SAMLException.RESPONDER,
								"The Shibboleth IdP currently only supports signing with RSA and DSA keys.");
					}

					assertion.sign(assertionAlgorithm, relyingParty.getIdentityProvider().getSigningCredential()
							.getPrivateKey(), Arrays.asList(relyingParty.getIdentityProvider().getSigningCredential()
							.getX509CertificateChain()));
				}
			}
		}

		// Sign the response, if appropriate
		if (signResponse && relyingParty.getIdentityProvider().getSigningCredential() != null
				&& relyingParty.getIdentityProvider().getSigningCredential().getPrivateKey() != null) {

			String responseAlgorithm;
			if (relyingParty.getIdentityProvider().getSigningCredential().getCredentialType() == Credential.RSA) {
				responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			} else if (relyingParty.getIdentityProvider().getSigningCredential().getCredentialType() == Credential.DSA) {
				responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
			} else {
				throw new InvalidCryptoException(SAMLException.RESPONDER,
						"The Shibboleth IdP currently only supports signing with RSA and DSA keys.");
			}

			response.sign(responseAlgorithm, relyingParty.getIdentityProvider().getSigningCredential().getPrivateKey(),
					Arrays.asList(relyingParty.getIdentityProvider().getSigningCredential().getX509CertificateChain()));
		}
	}

	protected void addFederationProvider(Element element) {

		log.debug("Found Federation Provider configuration element.");
		if (!element.getTagName().equals("FederationProvider")) {
			log.error("Error while attemtping to load Federation Provider.  Malformed provider specificaion.");
			return;
		}

		try {
			fedMetadata.add(FederationProviderFactory.loadProvider(element));
		} catch (MetadataException e) {
			log.error("Unable to load Federation Provider.  Skipping...");
		}
	}

	public int providerCount() {

		return fedMetadata.size();
	}

	public EntityDescriptor lookup(String providerId) {

		Iterator iterator = fedMetadata.iterator();
		while (iterator.hasNext()) {
			EntityDescriptor provider = ((Metadata) iterator.next()).lookup(providerId);
			if (provider != null) { return provider; }
		}
		return null;
	}

	public EntityDescriptor lookup(Artifact artifact) {

		Iterator iterator = fedMetadata.iterator();
		while (iterator.hasNext()) {
			EntityDescriptor provider = ((Metadata) iterator.next()).lookup(artifact);
			if (provider != null) { return provider; }
		}
		return null;
	}

	public SAMLAttribute[] getReleaseAttributes(Principal principal, String requester, URL resource) throws AAException {

		try {
			URI[] potentialAttributes = arpEngine.listPossibleReleaseAttributes(principal, requester, resource);
			return getReleaseAttributes(principal, requester, resource, potentialAttributes);

		} catch (ArpProcessingException e) {
			log.error("An error occurred while processing the ARPs for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");
		}
	}

	public SAMLAttribute[] getReleaseAttributes(Principal principal, String requester, URL resource,
			URI[] attributeNames) throws AAException {

		try {
			AAAttributeSet attributeSet = new AAAttributeSet();
			for (int i = 0; i < attributeNames.length; i++) {
				AAAttribute attribute = new AAAttribute(attributeNames[i].toString());
				attributeSet.add(attribute);
			}

			return resolveAttributes(principal, requester, resource, attributeSet);

		} catch (SAMLException e) {
			log.error("An error occurred while creating attributes for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");

		} catch (ArpProcessingException e) {
			log.error("An error occurred while processing the ARPs for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");
		}
	}

	private SAMLAttribute[] resolveAttributes(Principal principal, String requester, URL resource,
			AAAttributeSet attributeSet) throws ArpProcessingException {

		resolver.resolveAttributes(principal, requester, attributeSet);
		arpEngine.filterAttributes(attributeSet, principal, requester, resource);
		return attributeSet.getAttributes();
	}

	/**
	 * Cleanup resources that won't be released when this object is garbage-collected
	 */
	public void destroy() {

		resolver.destroy();
		arpEngine.destroy();
	}
}

class Shibbolethv1SSOHandler extends ProtocolHandler {

	private static Logger log = Logger.getLogger(Shibbolethv1SSOHandler.class.getName());

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#validForRequest(javax.servlet.http.HttpServletRequest)
	 */
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
	public void processRequest(HttpServletRequest request, HttpServletResponse response, ProtocolSupport support)
			throws InvalidClientDataException, NameIdentifierMappingException, SAMLException, IOException,
			ServletException {

		// Ensure that we have the required data from the servlet container
		ProtocolSupport.validateEngineData(request);

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
		SAMLNameIdentifier nameId = support.getNameMapper().getNameIdentifierName(relyingParty.getHSNameFormatId(),
				new AuthNPrincipal(username), relyingParty, relyingParty.getIdentityProvider());

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
			ProtocolSupport.addSignatures(samlResponse, relyingParty, provider, true);
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
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.idp.IdPResponder.ProtocolHandler#getHandlerName()
	 */
	String getHandlerName() {

		// TODO Auto-generated method stub
		return "Shibboleth-v1-SSO";
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

		// TODO rename from hs.jsp to more appropriate name
		RequestDispatcher rd = req.getRequestDispatcher("/hs.jsp");
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

class ArtifactQueryHandler extends ProtocolHandler {

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#validForRequest(javax.servlet.http.HttpServletRequest)
	 */
	boolean validForRequest(HttpServletRequest request) {

		// TODO Auto-generated method stub
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#getHandlerName()
	 */
	String getHandlerName() {

		// TODO change
		return "foo";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse, edu.internet2.middleware.shibboleth.idp.ProtocolSupport)
	 */
	public void processRequest(HttpServletRequest request, HttpServletResponse response, ProtocolSupport support)
			throws SAMLException, InvalidClientDataException, NameIdentifierMappingException, IOException,
			ServletException {

	// TODO Auto-generated method stub

	}

}

// TODO should this name say something about SSO?

abstract class ProtocolHandler {

	abstract boolean validForRequest(HttpServletRequest request);

	abstract String getHandlerName();

	/**
	 * @param request
	 * @param response
	 * @throws ServletException
	 */
	// TODO add javadoc
	// TODO should the name identifier mapping exception really be thrown here or covered up?
	public abstract void processRequest(HttpServletRequest request, HttpServletResponse response,
			ProtocolSupport support) throws SAMLException, InvalidClientDataException, NameIdentifierMappingException,
			IOException, ServletException;
}

class FederationProviderFactory {

	private static Logger log = Logger.getLogger(FederationProviderFactory.class.getName());

	public static Metadata loadProvider(Element e) throws MetadataException {

		String className = e.getAttribute("type");
		if (className == null || className.equals("")) {
			log.error("Federation Provider requires specification of the attribute \"type\".");
			throw new MetadataException("Failed to initialize Federation Provider.");
		} else {
			try {
				Class[] params = {Class.forName("org.w3c.dom.Element"),};
				return (Metadata) Class.forName(className).getConstructor(params).newInstance(new Object[]{e});
			} catch (Exception loaderException) {
				log.error("Failed to load Federation Provider implementation class: " + loaderException);
				Throwable cause = loaderException.getCause();
				while (cause != null) {
					log.error("caused by: " + cause);
					cause = cause.getCause();
				}
				throw new MetadataException("Failed to initialize Federation Provider.");
			}
		}
	}
}