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

import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLException;
import org.opensaml.SAMLIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.aa.AAConfig;
import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.aa.AARelyingParty;
import edu.internet2.middleware.shibboleth.aa.AAResponder;
import edu.internet2.middleware.shibboleth.aa.AAServiceProviderMapper;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolverException;
import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.OriginConfig;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.SAMLBindingFactory;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibPOSTProfile;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.ShibbolethOriginConfig;
import edu.internet2.middleware.shibboleth.common.TargetFederationComponent;
import edu.internet2.middleware.shibboleth.hs.HSRelyingParty;
import edu.internet2.middleware.shibboleth.metadata.AttributeConsumerRole;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Provider;
import edu.internet2.middleware.shibboleth.metadata.ProviderRole;

/**
 * Primary entry point for requests to the SAML IdP. Listens on multiple endpoints, routes requests to the appropriate
 * IdP processing components, and delivers proper protocol responses.
 * 
 * @author Walter Hoehn
 */

public class IdPResponder extends TargetFederationComponent {

	//TODO Maybe should rethink the inheritance here, since there is only one
	// servlet

	private static Logger			transactionLog	= Logger.getLogger("Shibboleth-TRANSACTION");

	private static Logger			log				= Logger.getLogger(IdPResponder.class.getName());

	private SAMLBinding				binding;

	//TODO Need to init
	private ArtifactRepository		artifactRepository;

	//TODO Obviously this has got to be unified
	private AAConfig				configuration;

	//TODO Need to init
	private NameMapper				nameMapper;

	//TODO Need to init
	private AAServiceProviderMapper	targetMapper;

	//TODO Need to rename, rework, and init
	private AAResponder				responder;

	public void init() throws ServletException {

		super.init();
		MDC.put("serviceId", "[IdP] Core");
		log.info("Initializing Identity Provider.");

		try {
			binding = SAMLBindingFactory.getInstance(SAMLBinding.SAML_SOAP_HTTPS);
			nameMapper = new NameMapper();
			loadConfiguration();
			log.info("Identity Provider initialization complete.");

		} catch (ShibbolethConfigurationException ae) {
			log.fatal("The Identity Provider could not be initialized: " + ae);
			throw new UnavailableException("Identity Provider failed to initialize.");
		} catch (SAMLException se) {
			log.fatal("SAML SOAP binding could not be loaded: " + se);
			throw new UnavailableException("Identity Provider failed to initialize.");
		}
	}

	private void loadConfiguration() throws ShibbolethConfigurationException {
		Document originConfig = OriginConfig.getOriginConfig(this.getServletContext());

		//TODO I think some of the failure cases here are different than in the
		// HS, so when the loadConfiguration() is unified, that must be taken
		// into account

		//TODO do we need to check active endpoints to determine which
		// components to load, for instance artifact repository, arp engine,
		// attribute resolver

		//Load global configuration properties
		//TODO make AA and HS config unified
		configuration = new AAConfig(originConfig.getDocumentElement());

		//Load name mappings
		NodeList itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(
				NameIdentifierMapping.mappingNamespace, "NameMapping");

		for (int i = 0; i < itemElements.getLength(); i++) {
			try {
				nameMapper.addNameMapping((Element) itemElements.item(i));
			} catch (NameIdentifierMappingException e) {
				log.error("Name Identifier mapping could not be loaded: " + e);
			}
		}

		//Load signing credentials
		itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(Credentials.credentialsNamespace,
				"Credentials");
		if (itemElements.getLength() < 1) {
			log.error("No credentials specified.");
		}
		if (itemElements.getLength() > 1) {
			log.error("Multiple Credentials specifications found, using first.");
		}
		Credentials credentials = new Credentials((Element) itemElements.item(0));

		//Load metadata
		itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(
				ShibbolethOriginConfig.originConfigNamespace, "FederationProvider");
		for (int i = 0; i < itemElements.getLength(); i++) {
			addFederationProvider((Element) itemElements.item(i));
		}
		if (providerCount() < 1) {
			log.error("No Federation Provider metadata loaded.");
			throw new ShibbolethConfigurationException("Could not load federation metadata.");
		}

		//Load relying party config
		try {
			//TODO unify the service provider mapper
			targetMapper = new AAServiceProviderMapper(originConfig.getDocumentElement(), configuration, credentials,
					this);
		} catch (ServiceProviderMapperException e) {
			log.error("Could not load Identity Provider configuration: " + e);
			throw new ShibbolethConfigurationException("Could not load Identity Provider configuration.");
		}

		try {
			//Startup Attribute Resolver
			AttributeResolver resolver = new AttributeResolver(configuration);

			//Startup ARP Engine
			ArpEngine arpEngine = null;
			itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(
					ShibbolethOriginConfig.originConfigNamespace, "ReleasePolicyEngine");

			if (itemElements.getLength() > 1) {
				log.warn("Encountered multiple <ReleasePolicyEngine> configuration elements.  Using first...");
			}
			if (itemElements.getLength() < 1) {
				arpEngine = new ArpEngine();
			} else {
				arpEngine = new ArpEngine((Element) itemElements.item(0));
			}

			//Startup responder
			responder = new AAResponder(arpEngine, resolver);

		} catch (ArpException ae) {
			log.fatal("The Identity Provider could not be initialized "
					+ "due to a problem with the ARP Engine configuration: " + ae);
			throw new ShibbolethConfigurationException("Could not load ARP Engine.");
		} catch (AttributeResolverException ne) {
			log.fatal("The Identity Provider could not be initialized due "
					+ "to a problem with the Attribute Resolver configuration: " + ne);
			throw new ShibbolethConfigurationException("Could not load Attribute Resolver.");
		}

	}

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MDC.put("serviceId", "[IdP] " + new SAMLIdentifier().toString());
		MDC.put("remoteAddr", request.getRemoteAddr());
		log.debug("Recieved a request via POST.");

		// Parse SOAP request and marshall SAML request object
		SAMLRequest samlRequest = null;
		try {
			try {
				samlRequest = binding.receive(request);
			} catch (SAMLException e) {
				log.fatal("Unable to parse request: " + e);
				throw new SAMLException("Invalid request data.");
			}

			// Determine the request type
			Iterator artifacts = samlRequest.getArtifacts();
			if (artifacts.hasNext()) {
				artifacts = null; // get rid of the iterator
				log.info("Recieved a request to dereference an assertion artifact.");
				processArtifactDereference(samlRequest, request, response);
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
				//TODO once again, ifgure out passThruErrors
				if (false) {
					//if (relyingParty.passThruErrors()) {
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
				//TODO figure out how to implement the passThru error handling
				// below
				//if (relyingParty != null && relyingParty.passThruErrors()) {
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

	//TODO get rid of this AAException thing
	private void processAttributeQuery(SAMLRequest samlRequest, HttpServletRequest request, HttpServletResponse response)
			throws SAMLException, IOException, ServletException, AAException, InvalidNameIdentifierException,
			NameIdentifierMappingException {
		//TODO validate that the endpoint is valid for the request type

		AARelyingParty relyingParty = null;

		SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

		if (!fromLegacyProvider(request)) {
			log.info("Remote provider has identified itself as: (" + attributeQuery.getResource() + ").");
		}

		//This is the requester name that will be passed to subsystems
		String effectiveName = null;

		X509Certificate credential = getCredentialFromProvider(request);
		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request is from an unauthenticated service provider.");
		} else {

			//Identify a Relying Party
			relyingParty = targetMapper.getRelyingParty(attributeQuery.getResource());

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
			relyingParty = targetMapper.getRelyingParty(null);
		}

		//Fail if we can't honor SAML Subject Confirmation
		if (!fromLegacyProvider(request)) {
			Iterator iterator = attributeQuery.getSubject().getConfirmationMethods();
			boolean hasConfirmationMethod = false;
			while (iterator.hasNext()) {
				log.info("Request contains SAML Subject Confirmation method: (" + (String) iterator.next() + ").");
			}
			if (hasConfirmationMethod) { throw new SAMLException(SAMLException.REQUESTER,
					"This SAML authority cannot honor requests containing the supplied SAML Subject Confirmation Method."); }
		}

		//Map Subject to local principal
		Principal principal = nameMapper.getPrincipal(attributeQuery.getSubject().getName(), relyingParty, relyingParty
				.getIdentityProvider());
		log.info("Request is for principal (" + principal.getName() + ").");
		//TODO probably need to move this error handing out

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

			attrs = responder.getReleaseAttributes(principal, effectiveName, null, (URI[]) requestedAttrs
					.toArray(new URI[0]));
		} else {
			log.info("Request does not designate specific attributes, resolving all available.");
			attrs = responder.getReleaseAttributes(principal, effectiveName, null);
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

	private void processArtifactDereference(SAMLRequest samlRequest, HttpServletRequest request,
			HttpServletResponse response) throws SAMLException, IOException {
		//TODO validate that the endpoint is valid for the request type
		//TODO how about signatures on artifact dereferencing

		// Pull credential from request
		X509Certificate credential = getCredentialFromProvider(request);
		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request is from an unauthenticated service provider.");
			throw new SAMLException(SAMLException.REQUESTER,
					"SAML Artifacts cannot be dereferenced for unauthenticated requesters.");
		}

		log.info("Request contains credential: (" + credential.getSubjectX500Principal().getName(X500Principal.RFC2253)
				+ ").");

		ArrayList assertions = new ArrayList();
		Iterator artifacts = samlRequest.getArtifacts();

		int queriedArtifacts = 0;
		StringBuffer dereferencedArtifacts = new StringBuffer(); //for
		// transaction
		// log
		while (artifacts.hasNext()) {
			queriedArtifacts++;
			String artifact = (String) artifacts.next();
			log.debug("Attempting to dereference artifact: (" + artifact + ").");
			ArtifactMapping mapping = artifactRepository.recoverAssertion(artifact);
			if (mapping != null) {
				SAMLAssertion assertion = mapping.getAssertion();

				//See if we have metadata for this provider
				Provider provider = lookup(mapping.getServiceProviderId());
				if (provider == null) {
					log.info("No metadata found for provider: (" + mapping.getServiceProviderId() + ").");
					throw new SAMLException(SAMLException.REQUESTER, "Invalid service provider.");
				}

				//Make sure that the suppplied credential is valid for the
				// provider to which the artifact was issued
				if (!isValidCredential(provider, credential)) {
					log.error("Supplied credential ("
							+ credential.getSubjectX500Principal().getName(X500Principal.RFC2253)
							+ ") is NOT valid for provider (" + mapping.getServiceProviderId()
							+ "), to whom this artifact was issued.");
					throw new SAMLException(SAMLException.REQUESTER, "Invalid credential.");
				}

				log.debug("Supplied credential validated for the provider to which this artifact was issued.");

				assertions.add(assertion);
				dereferencedArtifacts.append("(" + artifact + ")");
			}
		}

		//The spec requires that if any artifacts are dereferenced, they must
		// all be dereferenced
		if (assertions.size() > 0 & assertions.size() != queriedArtifacts) { throw new SAMLException(
				SAMLException.REQUESTER, "Unable to successfully dereference all artifacts."); }

		//Create and send response
		SAMLResponse samlResponse = new SAMLResponse(samlRequest.getId(), null, assertions, null);

		if (log.isDebugEnabled()) {
			try {
				log.debug("Dumping generated SAML Response:"
						+ System.getProperty("line.separator")
						+ new String(new BASE64Decoder().decodeBuffer(new String(samlResponse.toBase64(), "ASCII")),
								"UTF8"));
			} catch (SAMLException e) {
				log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
			} catch (IOException e) {
				log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
			}
		}

		binding.respond(response, samlResponse, null);

		transactionLog.info("Succesfully dereferenced the following artifacts: " + dereferencedArtifacts.toString());
		//TODO make sure we can delete this junk below
		/*
		 * } catch (Exception e) { log.error("Error while processing request: " + e); try { sendFailure(res,
		 * samlRequest, new SAMLException(SAMLException.RESPONDER, "General error processing request.")); return; }
		 * catch (Exception ee) { log.fatal("Could not construct a SAML error response: " + ee); throw new
		 * ServletException("Handle Service response failure."); } }
		 */
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MDC.put("serviceId", "[IdP] " + new SAMLIdentifier().toString());
		MDC.put("remoteAddr", request.getRemoteAddr());
		log.debug("Recieved a request via GET.");
	}

	private static X509Certificate getCredentialFromProvider(HttpServletRequest req) {
		X509Certificate[] certArray = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
		if (certArray != null && certArray.length > 0) { return certArray[0]; }
		return null;
	}

	private static boolean isValidCredential(Provider provider, X509Certificate certificate) {

		ProviderRole[] roles = provider.getRoles();
		if (roles.length == 0) {
			log.info("Inappropriate metadata for provider.");
			return false;
		}
		//TODO figure out what to do about this role business here
		for (int i = 0; roles.length > i; i++) {
			if (roles[i] instanceof AttributeConsumerRole) {
				KeyDescriptor[] descriptors = roles[i].getKeyDescriptors();
				for (int j = 0; descriptors.length > j; j++) {
					KeyInfo[] keyInfo = descriptors[j].getKeyInfo();
					for (int k = 0; keyInfo.length > k; k++) {
						for (int l = 0; keyInfo[k].lengthKeyName() > l; l++) {
							try {

								//First, try to match DN against metadata
								try {
									if (certificate.getSubjectX500Principal().getName(X500Principal.RFC2253).equals(
											new X500Principal(keyInfo[k].itemKeyName(l).getKeyName())
													.getName(X500Principal.RFC2253))) {
										log.debug("Matched against DN.");
										return true;
									}
								} catch (IllegalArgumentException iae) {
									//squelch this runtime exception, since
									// this might be a valid case
								}

								//If that doesn't work, we try matching against
								// some Subject Alt Names
								try {
									Collection altNames = certificate.getSubjectAlternativeNames();
									if (altNames != null) {
										for (Iterator nameIterator = altNames.iterator(); nameIterator.hasNext();) {
											List altName = (List) nameIterator.next();
											if (altName.get(0).equals(new Integer(2))
													|| altName.get(0).equals(new Integer(6))) { //2 is
												// DNS,
												// 6 is
												// URI
												if (altName.get(1).equals(keyInfo[k].itemKeyName(l).getKeyName())) {
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

								//If that doesn't work, try to match using
								// SSL-style hostname matching
								if (ShibPOSTProfile.getHostNameFromDN(certificate.getSubjectX500Principal()).equals(
										keyInfo[k].itemKeyName(l).getKeyName())) {
									log.debug("Matched against hostname.");
									return true;
								}

							} catch (XMLSecurityException e) {
								log.error("Encountered an error reading federation metadata: " + e);
							}
						}
					}
				}
			}
		}
		log.info("Supplied credential not found in metadata.");
		return false;
	}

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
			binding.respond(httpResponse, null, exception);
			log.error("Identity Provider failed to make an error message: " + se);
		}
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

	private String getEffectiveName(HttpServletRequest req, AARelyingParty relyingParty)
			throws InvalidProviderCredentialException {

		//X500Principal credentialName = getCredentialName(req);
		X509Certificate credential = getCredentialFromProvider(req);

		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request is from an unauthenticated service provider.");
			return null;

		} else {
			log.info("Request contains credential: ("
					+ credential.getSubjectX500Principal().getName(X500Principal.RFC2253) + ").");
			//Mockup old requester name for requests from < 1.2 targets
			if (fromLegacyProvider(req)) {
				String legacyName = ShibPOSTProfile.getHostNameFromDN(credential.getSubjectX500Principal());
				if (legacyName == null) {
					log.error("Unable to extract legacy requester name from certificate subject.");
				}

				log.info("Request from legacy service provider: (" + legacyName + ").");
				return legacyName;

			} else {

				//See if we have metadata for this provider
				Provider provider = lookup(relyingParty.getProviderId());
				if (provider == null) {
					log.info("No metadata found for provider: (" + relyingParty.getProviderId() + ").");
					log.info("Treating remote provider as unauthenticated.");
					return null;
				}

				//Make sure that the suppplied credential is valid for the
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

	//TODO this should be renamed, since it is now only one type of response
	// that we can send
	public void sendSAMLResponse(HttpServletResponse resp, SAMLAttribute[] attrs, SAMLRequest samlRequest,
			RelyingParty relyingParty, SAMLException exception) throws IOException {

		SAMLException ourSE = null;
		SAMLResponse samlResponse = null;

		try {
			if (attrs == null || attrs.length == 0) {
				//No attribute found
				samlResponse = new SAMLResponse(samlRequest.getId(), null, null, exception);
			} else {

				SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

				//Reference requested subject
				SAMLSubject rSubject = (SAMLSubject) attributeQuery.getSubject().clone();

				//Set appropriate audience
				ArrayList audiences = new ArrayList();
				if (relyingParty.getProviderId() != null) {
					audiences.add(relyingParty.getProviderId());
				}
				if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
					audiences.add(relyingParty.getName());
				}
				SAMLCondition condition = new SAMLAudienceRestrictionCondition(audiences);

				//Put all attributes into an assertion
				SAMLStatement statement = new SAMLAttributeStatement(rSubject, Arrays.asList(attrs));

				//Set assertion expiration to longest attribute expiration
				long max = 0;
				for (int i = 0; i < attrs.length; i++) {
					if (max < attrs[i].getLifetime()) {
						max = attrs[i].getLifetime();
					}
				}
				Date now = new Date();
				Date then = new Date(now.getTime() + (max * 1000)); //max is in
				// seconds

				SAMLAssertion sAssertion = new SAMLAssertion(relyingParty.getIdentityProvider().getProviderId(), now,
						then, Collections.singleton(condition), null, Collections.singleton(statement));

				samlResponse = new SAMLResponse(samlRequest.getId(), null, Collections.singleton(sAssertion), exception);
				addSignatures(samlResponse, relyingParty);
			}
		} catch (SAMLException se) {
			ourSE = se;
		} catch (CloneNotSupportedException ex) {
			ourSE = new SAMLException(SAMLException.RESPONDER, ex);

		} finally {

			if (log.isDebugEnabled()) {
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

			binding.respond(resp, samlResponse, ourSE);
		}
	}

	private static void addSignatures(SAMLResponse reponse, RelyingParty relyingParty) throws SAMLException {

		//Sign the assertions, if appropriate
		if (relyingParty.getIdentityProvider().getAssertionSigningCredential() != null
				&& relyingParty.getIdentityProvider().getAssertionSigningCredential().getPrivateKey() != null) {

			String assertionAlgorithm;
			if (relyingParty.getIdentityProvider().getAssertionSigningCredential().getCredentialType() == Credential.RSA) {
				assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			} else if (relyingParty.getIdentityProvider().getAssertionSigningCredential().getCredentialType() == Credential.DSA) {
				assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
			} else {
				throw new InvalidCryptoException(SAMLException.RESPONDER,
						"ShibPOSTProfile.prepare() currently only supports signing with RSA and DSA keys.");
			}

			((SAMLAssertion) reponse.getAssertions().next()).sign(assertionAlgorithm, relyingParty
					.getIdentityProvider().getAssertionSigningCredential().getPrivateKey(), Arrays.asList(relyingParty
					.getIdentityProvider().getAssertionSigningCredential().getX509CertificateChain()));
		}

		//Sign the response, if appropriate
		if (relyingParty.getIdentityProvider().getResponseSigningCredential() != null
				&& relyingParty.getIdentityProvider().getResponseSigningCredential().getPrivateKey() != null) {

			String responseAlgorithm;
			if (relyingParty.getIdentityProvider().getResponseSigningCredential().getCredentialType() == Credential.RSA) {
				responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			} else if (relyingParty.getIdentityProvider().getResponseSigningCredential().getCredentialType() == Credential.DSA) {
				responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
			} else {
				throw new InvalidCryptoException(SAMLException.RESPONDER,
						"ShibPOSTProfile.prepare() currently only supports signing with RSA and DSA keys.");
			}

			reponse.sign(responseAlgorithm, relyingParty.getIdentityProvider().getResponseSigningCredential()
					.getPrivateKey(), Arrays.asList(relyingParty.getIdentityProvider().getResponseSigningCredential()
					.getX509CertificateChain()));
		}
	}

	class InvalidProviderCredentialException extends Exception {

		public InvalidProviderCredentialException(String message) {
			super(message);
		}
	}

	abstract class ArtifactRepository {

		// TODO figure out what to do about this interface long term
		abstract String addAssertion(SAMLAssertion assertion, HSRelyingParty relyingParty);

		abstract ArtifactMapping recoverAssertion(String artifact);
	}

	class ArtifactMapping {

		//TODO figure out what to do about this interface long term
		private String			assertionHandle;

		private long			expirationTime;

		private SAMLAssertion	assertion;

		private String			serviceProviderId;

		ArtifactMapping(String assertionHandle, SAMLAssertion assertion, ServiceProvider sp) {
			this.assertionHandle = assertionHandle;
			this.assertion = assertion;
			expirationTime = System.currentTimeMillis() + (1000 * 60 * 5); //in 5
			// minutes
			serviceProviderId = sp.getProviderId();
		}

		boolean isExpired() {
			if (System.currentTimeMillis() > expirationTime) { return true; }
			return false;
		}

		boolean isCorrectProvider(ServiceProvider sp) {
			if (sp.getProviderId().equals(serviceProviderId)) { return true; }
			return false;
		}

		SAMLAssertion getAssertion() {
			return assertion;
		}

		String getServiceProviderId() {
			return serviceProviderId;
		}
	}
}