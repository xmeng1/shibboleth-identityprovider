/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution, if any, must include the following acknowledgment: "This product includes
 * software developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2
 * Project. Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2,
 * nor the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please
 * contact shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name,
 * without prior written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 * NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS
 * WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED
 * INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
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
import edu.internet2.middleware.shibboleth.common.SAMLBindingFactory;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.ShibbolethOriginConfig;
import edu.internet2.middleware.shibboleth.common.TargetFederationComponent;
import edu.internet2.middleware.shibboleth.metadata.AttributeConsumerRole;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Provider;
import edu.internet2.middleware.shibboleth.metadata.ProviderRole;

/**
 * @author Walter Hoehn
 */

public class AAServlet extends TargetFederationComponent {

	private AAConfig				configuration;
	protected AAResponder			responder;
	private NameMapper				nameMapper;
	private SAMLBinding				binding;
	private static Logger			transactionLog	= Logger.getLogger("Shibboleth-TRANSACTION");
	private AAServiceProviderMapper	targetMapper;

	private static Logger			log				= Logger.getLogger(AAServlet.class.getName());
	protected Pattern				regex			= Pattern.compile(".*CN=([^,/]+).*");

	public void init() throws ServletException {
		super.init();

		MDC.put("serviceId", "[AA] Core");
		log.info("Initializing Attribute Authority.");

		try {
			nameMapper = new NameMapper();
			loadConfiguration();

			binding = SAMLBindingFactory.getInstance(SAMLBinding.SAML_SOAP_HTTPS);

			log.info("Attribute Authority initialization complete.");

		} catch (ShibbolethConfigurationException ae) {
			log.fatal("The AA could not be initialized: " + ae);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (SAMLException se) {
			log.fatal("SAML SOAP binding could not be loaded: " + se);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		}
	}

	protected void loadConfiguration() throws ShibbolethConfigurationException {

		Document originConfig = OriginConfig.getOriginConfig(this.getServletContext());

		//Load global configuration properties
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
			targetMapper = new AAServiceProviderMapper(originConfig.getDocumentElement(), configuration, credentials,
					this);
		} catch (ServiceProviderMapperException e) {
			log.error("Could not load origin configuration: " + e);
			throw new ShibbolethConfigurationException("Could not load origin configuration.");
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
			log.fatal("The AA could not be initialized due to a problem with the ARP Engine configuration: " + ae);
			throw new ShibbolethConfigurationException("Could not load ARP Engine.");
		} catch (AttributeResolverException ne) {
			log.fatal("The AA could not be initialized due to a problem with the Attribute Resolver configuration: "
					+ ne);
			throw new ShibbolethConfigurationException("Could not load Attribute Resolver.");
		}

	}

	public void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		MDC.put("serviceId", "[AA] " + new SAMLIdentifier().toString());
		MDC.put("remoteAddr", req.getRemoteAddr());
		log.info("Handling request.");

		AARelyingParty relyingParty = null;

		//Parse SOAP request
		SAMLRequest samlRequest = null;

		try {

			try {
				samlRequest = binding.receive(req);

			} catch (SAMLException e) {
				log.fatal("Unable to parse request: " + e);
				throw new AAException("Invalid request data.");
			}

			if (samlRequest.getQuery() == null || !(samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
				throw new SAMLException(SAMLException.REQUESTER,
						"This SAML authority only responds to attribute queries.");
			}
			SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

			//Identify a Relying Party
			relyingParty = targetMapper.getRelyingParty(attributeQuery.getResource());

			//This is the requester name that will be passed to subsystems
			String effectiveName = getEffectiveName(req, relyingParty);

			if (effectiveName == null) {
				log.debug("Using default Relying Party for unauthenticated provider.");
				relyingParty = targetMapper.getRelyingParty(null);
			}

			//Map Subject to local principal
			if (relyingParty.getIdentityProvider().getProviderId() != null
					&& !relyingParty.getIdentityProvider().getProviderId().equals(
							attributeQuery.getSubject().getName().getNameQualifier())) {
				log.error("The name qualifier for the referenced subject ("
						+ attributeQuery.getSubject().getName().getNameQualifier()
						+ ") is not valid for this identiy provider.");
				throw new NameIdentifierMappingException("The name qualifier for the referenced subject ("
						+ attributeQuery.getSubject().getName().getNameQualifier()
						+ ") is not valid for this identiy provider.");
			}

			Principal principal = null;
			try {
				// for testing
				if (attributeQuery.getSubject().getName().getFormat().equals("urn:mace:shibboleth:test:nameIdentifier")) {
					principal = new AuthNPrincipal("test-handle");
				} else {
					principal = nameMapper.getPrincipal(attributeQuery.getSubject().getName(), relyingParty,
							relyingParty.getIdentityProvider());
				}
				log.info("Request is for principal (" + principal.getName() + ").");

			} catch (InvalidNameIdentifierException invalidNameE) {
				log.info("Could not associate the request subject with a principal: " + invalidNameE);
				try {
					if (relyingParty.passThruErrors()) {
						sendFailure(resp, samlRequest, new SAMLException(Arrays
								.asList(invalidNameE.getSAMLErrorCodes()), "The supplied Subject was unrecognized.",
								invalidNameE));

					} else {
						sendFailure(resp, samlRequest, new SAMLException(Arrays
								.asList(invalidNameE.getSAMLErrorCodes()), "The supplied Subject was unrecognized."));
					}
					return;
				} catch (Exception ee) {
					log.fatal("Could not construct a SAML error response: " + ee);
					throw new ServletException("Attribute Authority response failure.");
				}
			}

			SAMLAttribute[] attrs;
			Iterator requestedAttrsIterator = attributeQuery.getDesignators();
			if (requestedAttrsIterator.hasNext()) {
				log.info("Request designates specific attributes, resolving this set.");
				ArrayList requestedAttrs = new ArrayList();
				while (requestedAttrsIterator.hasNext()) {
					SAMLAttribute attribute = (SAMLAttribute) requestedAttrsIterator.next();
					try {
						log.debug("Designated attribute: (" + attribute.getName() + ")");
						requestedAttrs.add(new URI(attribute.getName()));
					} catch (URISyntaxException use) {
						log
								.error("Request designated an attribute name that does not conform to the required URI syntax ("
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
			sendResponse(resp, attrs, samlRequest, relyingParty, null);
			log.info("Successfully responded about " + principal.getName());

			if (effectiveName == null) {
				if (fromLegacyProvider(req)) {
					transactionLog.info("Attribute assertion issued to anonymous legacy provider at ("
							+ req.getRemoteAddr() + ").");
				} else {
					transactionLog.info("Attribute assertion issued to anonymous provider at (" + req.getRemoteAddr()
							+ ").");
				}
			} else {
				if (fromLegacyProvider(req)) {
					transactionLog.info("Attribute assertion issued to legacy provider: (" + effectiveName + ").");
				} else {
					transactionLog.info("Attribute assertion issued to provider: (" + effectiveName + ").");
				}
			}

		} catch (Exception e) {
			log.error("Error while processing request: " + e);
			try {
				if (relyingParty != null && relyingParty.passThruErrors()) {
					sendFailure(resp, samlRequest, new SAMLException(SAMLException.RESPONDER,
							"General error processing request.", e));
				} else if (configuration.passThruErrors()) {
					sendFailure(resp, samlRequest, new SAMLException(SAMLException.RESPONDER,
							"General error processing request.", e));
				} else {
					sendFailure(resp, samlRequest, new SAMLException(SAMLException.RESPONDER,
							"General error processing request."));
				}
				return;
			} catch (Exception ee) {
				log.fatal("Could not construct a SAML error response: " + ee);
				throw new ServletException("Attribute Authority response failure.");
			}

		}
	}

	protected String getEffectiveName(HttpServletRequest req, AARelyingParty relyingParty) throws AAException {

		String credentialName = getCredentialName(req);
		if (credentialName == null || credentialName.toString().equals("")) {
			log.info("Request is from an unauthenticated service provider.");
			return null;

		} else {
			log.info("Request contains credential: (" + credentialName + ").");
			//Mockup old requester name for requests from < 1.2 targets
			if (fromLegacyProvider(req)) {
				String legacyName = getLegacyRequesterName(credentialName);
				log.info("Request from legacy service provider: (" + legacyName + ").");
				return legacyName;

			} else {
				//Make sure that the suppplied credential is valid for the selected relying party
				if (isValidCredential(relyingParty, credentialName.toString())) {
					log.info("Supplied credential validated for this provider.");
					log.info("Request from service provider: (" + relyingParty.getProviderId() + ").");
					return relyingParty.getProviderId();
				} else {
					log.error("Supplied credential (" + credentialName.toString() + ") is NOT valid for provider ("
							+ relyingParty.getProviderId() + ").");
					throw new AAException("Invalid credential.");
				}
			}
		}
	}

	private String getLegacyRequesterName(String credentialName) {
		Matcher matches = regex.matcher(credentialName);
		if (!matches.find() || matches.groupCount() > 1) {
			log.error("Unable to extract legacy requester name from certificate subject.");
			return null;
		}
		return matches.group(1);
	}

	public void destroy() {
		log.info("Cleaning up resources.");
		responder.destroy();
		nameMapper.destroy();
	}

	public void sendResponse(HttpServletResponse resp, SAMLAttribute[] attrs, SAMLRequest samlRequest,
			RelyingParty relyingParty, SAMLException exception) throws IOException {

		SAMLException ourSE = null;
		SAMLResponse samlResponse = null;

		try {
			if (attrs == null || attrs.length == 0) {
				//No attribute found
				samlResponse = new SAMLResponse(samlRequest.getId(), null, null, exception);
			} else {

				if (samlRequest.getQuery() == null || !(samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
					throw new SAMLException(SAMLException.REQUESTER,
							"This SAML authority only responds to attribute queries");
				}
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
				Date then = new Date(now.getTime() + (max * 1000)); //max is in seconds

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

	private void addSignatures(SAMLResponse reponse, RelyingParty relyingParty) throws SAMLException {

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

	public void sendFailure(HttpServletResponse httpResponse, SAMLRequest samlRequest, SAMLException exception)
			throws IOException {
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
			log.error("AA failed to make an error message: " + se);
		}
	}

	protected boolean isValidCredential(RelyingParty relyingParty, String credentialName) throws AAException {

		Provider provider = lookup(relyingParty.getProviderId());
		if (provider == null) {
			log.info("No metadata found for provider: (" + relyingParty.getProviderId() + ").");
			throw new AAException("Request is from an unkown Service Provider.");
		}

		ProviderRole[] roles = provider.getRoles();
		if (roles.length == 0) {
			log.info("Inappropriate metadata for provider.");
			return false;
		}

		for (int i = 0; roles.length > i; i++) {
			if (roles[i] instanceof AttributeConsumerRole) {
				KeyDescriptor[] descriptors = roles[i].getKeyDescriptors();
				for (int j = 0; descriptors.length > j; j++) {
					KeyInfo[] keyInfo = descriptors[j].getKeyInfo();
					for (int k = 0; keyInfo.length > k; k++) {
						for (int l = 0; keyInfo[k].lengthKeyName() > l; l++) {
							try {
								if (credentialName.equals(keyInfo[k].itemKeyName(l).getKeyName())) {
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

	protected boolean fromLegacyProvider(HttpServletRequest request) {
		String version = request.getHeader("Shibboleth");
		if (version != null) {
			log.debug("Request from Shibboleth version: " + version);
			return false;
		}
		log.debug("No version header found.");
		return true;
	}

	protected String getCredentialName(HttpServletRequest req) {
		X509Certificate[] certArray = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
		if (certArray != null && certArray.length > 0) {
			return certArray[0].getSubjectDN().getName();
		}
		return null;
	}

}
