/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution, if any, must include the
 * following acknowledgment: "This product includes software developed by the University Corporation for Advanced
 * Internet Development <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement may appear in the
 * software itself, if and wherever such third-party acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor the University Corporation for
 * Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote products derived from this software
 * without specific prior written permission. For written permission, please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the University Corporation
 * for Advanced Internet Development, nor may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.xerces.parsers.DOMParser;
import org.opensaml.QName;
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
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolverException;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.OriginComponent;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.SAMLBindingFactory;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.ShibbolethOriginConfig;

/**
 * @author Walter Hoehn
 */

public class AAServlet extends OriginComponent {

	private AAConfig configuration;
	protected AAResponder responder;
	private NameMapper nameMapper;
	private SAMLBinding binding;
	private static Logger transactionLog = Logger.getLogger("Shibboleth-TRANSACTION");
	private AAServiceProviderMapper targetMapper;

	private static Logger log = Logger.getLogger(AAServlet.class.getName());

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

		Document originConfig = getOriginConfig();

		//Load global configuration properties
		configuration = new AAConfig(originConfig.getDocumentElement());

		//Load name mappings
		NodeList itemElements =
			originConfig.getDocumentElement().getElementsByTagNameNS(
				NameIdentifierMapping.mappingNamespace,
				"NameMapping");

		for (int i = 0; i < itemElements.getLength(); i++) {
			try {
				nameMapper.addNameMapping((Element) itemElements.item(i));
			} catch (NameIdentifierMappingException e) {
				log.error("Name Identifier mapping could not be loaded: " + e);
			}
		}

		//Load relying party config
		try {
			targetMapper = new AAServiceProviderMapper(originConfig.getDocumentElement(), configuration);
		} catch (ServiceProviderMapperException e) {
			log.error("Could not load origin configuration: " + e);
			throw new ShibbolethConfigurationException("Could not load origin configuration.");
		}

		try {
			//Startup Attribute Resolver
			AttributeResolver resolver = new AttributeResolver(configuration);

			//Startup ARP Engine
			ArpEngine arpEngine = null;
			itemElements =
				originConfig.getDocumentElement().getElementsByTagNameNS(
					ShibbolethOriginConfig.originConfigNamespace,
					"ReleasePolicyEngine");

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
			log.fatal(
				"The AA could not be initialized due to a problem with the Attribute Resolver configuration: " + ne);
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
		StringBuffer credentialName = new StringBuffer();
		try {
			samlRequest = binding.receive(req, credentialName);

		} catch (SAMLException e) {
			log.fatal("Unable to parse request: " + e);
			throw new ServletException("Request failed.");
		}

		try {
			if (samlRequest.getQuery() == null || !(samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
				throw new SAMLException(
					SAMLException.REQUESTER,
					"This SAML authority only responds to attribute queries.");
			}
			SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

			//Identify a Relying Party
			if (attributeQuery.getResource() == null || attributeQuery.getResource().equals("")) {
				log.error("Request from an unidentified service provider.");
			}
			log.info("Request from service provider: (" + attributeQuery.getResource() + ").");
			relyingParty = targetMapper.getRelyingParty(attributeQuery.getResource());

			//Map Subject to local principal
			if (relyingParty.getProviderId() != null
				&& !relyingParty.getProviderId().equals(attributeQuery.getSubject().getName().getNameQualifier())) {
				log.error(
					"The name qualifier for the referenced subject ("
						+ attributeQuery.getSubject().getName().getNameQualifier()
						+ ") is not valid for this identiy provider.");
				throw new NameIdentifierMappingException(
					"The name qualifier for the referenced subject ("
						+ attributeQuery.getSubject().getName().getNameQualifier()
						+ ") is not valid for this identiy provider.");
			}

			Principal principal = null;
			try {
				if (attributeQuery.getSubject().getName().getName().equalsIgnoreCase("foo")) {
					// for testing
					principal = new AuthNPrincipal("test-handle");
				} else {
					principal =
						nameMapper.getPrincipal(
							attributeQuery.getSubject().getName(),
							relyingParty,
							relyingParty.getIdentityProvider());
				}
				log.info("Request is for principal (" + principal + ").");

				//TODO Do something about these silly passthru errors

			} catch (NameIdentifierMappingException e) {
				log.info("Could not associate the request subject with a principal: " + e);
				try {
					//TODO this doesn't always make sense anymore
					QName[] codes =
						{
							SAMLException.REQUESTER,
							new QName(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS, "InvalidHandle")};
					if (relyingParty.passThruErrors()) {
						sendFailure(
							resp,
							samlRequest,
							new SAMLException(Arrays.asList(codes), "The supplied Subject was unrecognized.", e));

					} else {
						sendFailure(
							resp,
							samlRequest,
							new SAMLException(Arrays.asList(codes), "The supplied Subject was unrecognized."));
					}
					return;
				} catch (Exception ee) {
					log.fatal("Could not construct a SAML error response: " + ee);
					throw new ServletException("Attribute Authority response failure.");
				}
			}

			if (credentialName == null || credentialName.toString().equals("")) {
				log.info("Request is from an unauthenticated service provider.");
			} else {
				log.info("Request is from service provider: (" + credentialName + ").");
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
						log.error(
							"Request designated an attribute name that does not conform to the required URI syntax ("
								+ attribute.getName()
								+ ").  Ignoring this attribute");
					}
				}
				attrs =
					responder.getReleaseAttributes(
						principal,
						credentialName.toString(),
						null,
						(URI[]) requestedAttrs.toArray(new URI[0]));
			} else {
				log.info("Request does not designate specific attributes, resolving all available.");
				attrs = responder.getReleaseAttributes(principal, credentialName.toString(), null);
			}

			log.info("Found " + attrs.length + " attribute(s) for " + principal.getName());
			sendResponse(resp, attrs, samlRequest, relyingParty, null);
			log.info("Successfully responded about " + principal.getName());

			//TODO place transaction log statement here

		} catch (Exception e) {
			log.error("Error while processing request: " + e);
			try {
				if (relyingParty != null && relyingParty.passThruErrors()) {
					sendFailure(
						resp,
						samlRequest,
						new SAMLException(SAMLException.RESPONDER, "General error processing request.", e));
				} else if (configuration.passThruErrors()) {
					sendFailure(
						resp,
						samlRequest,
						new SAMLException(SAMLException.RESPONDER, "General error processing request.", e));
				} else {
					sendFailure(
						resp,
						samlRequest,
						new SAMLException(SAMLException.RESPONDER, "General error processing request."));
				}
				return;
			} catch (Exception ee) {
				log.fatal("Could not construct a SAML error response: " + ee);
				throw new ServletException("Attribute Authority response failure.");
			}

		}
	}
	public void sendResponse(
		HttpServletResponse resp,
		SAMLAttribute[] attrs,
		SAMLRequest samlRequest,
		RelyingParty relyingParty,
		SAMLException exception)
		throws IOException {

		SAMLException ourSE = null;
		SAMLResponse samlResponse = null;

		try {
			if (attrs == null || attrs.length == 0) {
				//No attribute found
				samlResponse = new SAMLResponse(samlRequest.getId(), null, null, exception);
			} else {

				if (samlRequest.getQuery() == null || !(samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
					throw new SAMLException(
						SAMLException.REQUESTER,
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
				Date then = new Date(now.getTime() + max);

				SAMLAssertion sAssertion =
					new SAMLAssertion(
						relyingParty.getIdentityProvider().getProviderId(),
						now,
						then,
						Collections.singleton(condition),
						null,
						Collections.singleton(statement));

				samlResponse =
					new SAMLResponse(samlRequest.getId(), null, Collections.singleton(sAssertion), exception);
			}
		} catch (SAMLException se) {
			ourSE = se;
		} catch (CloneNotSupportedException ex) {
			ourSE = new SAMLException(SAMLException.RESPONDER, ex);

		} finally {

			if (log.isDebugEnabled()) {
				try {
					log.debug(
						"Dumping generated SAML Response:"
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

	public void sendFailure(HttpServletResponse httpResponse, SAMLRequest samlRequest, SAMLException exception)
		throws IOException {
		try {
			SAMLResponse samlResponse =
				new SAMLResponse((samlRequest != null) ? samlRequest.getId() : null, null, null, exception);
			if (log.isDebugEnabled()) {
				try {
					log.debug(
						"Dumping generated SAML Error Response:"
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

}
