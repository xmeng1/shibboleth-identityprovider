/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
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
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolverException;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.SAMLBindingFactory;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibbolethOriginConfig;

/**
 * @author Walter Hoehn
 */

public class AAServlet extends HttpServlet {

	private ShibbolethOriginConfig configuration;
	protected AAResponder responder;
	private NameMapper nameMapper;
	private SAMLBinding binding;
	private static Logger transactionLog = Logger.getLogger("Shibboleth-TRANSACTION");
	private ServiceProviderMapper targetMapper;

	private static Logger log = Logger.getLogger(AAServlet.class.getName());

	public void init() throws ServletException {
		super.init();

		MDC.put("serviceId", "[AA] Core");
		log.info("Initializing Attribute Authority.");

		try {
			
			nameMapper = new NameMapper();
			loadConfiguration();

			//TODO pass in real config
			ArpEngine arpEngine = new ArpEngine(null);
			AttributeResolver resolver = new AttributeResolver(null);

			responder = new AAResponder(arpEngine, resolver);

			binding = SAMLBindingFactory.getInstance(SAMLBinding.SAML_SOAP_HTTPS);

			log.info("Attribute Authority initialization complete.");

		} catch (ArpException ae) {
			log.fatal("The AA could not be initialized due to a problem with the ARP Engine configuration: " + ae);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (AttributeResolverException ne) {
			log.fatal(
				"The AA could not be initialized due to a problem with the Attribute Resolver configuration: " + ne);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (AAException ae) {
			log.fatal("The AA could not be initialized: " + ae);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (SAMLException se) {
			log.fatal("SAML SOAP binding could not be loaded: " + se);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		}

	}
	protected void loadConfiguration() throws AAException {

		//TODO could maybe factor some of the common stuff up a level.

		DOMParser parser = loadParser(true);

		String originConfigFile = getInitParameter("OriginConfigFile");
		if (originConfigFile == null) {
			originConfigFile = "/conf/origin.xml";
		}

		log.debug("Loading Configuration from (" + originConfigFile + ").");

		try {
			parser.parse(new InputSource(new ShibResource(originConfigFile, this.getClass()).getInputStream()));

		} catch (SAXException e) {
			log.error("Error while parsing origin configuration: " + e);
			throw new AAException("Error while parsing origin configuration.");
		} catch (IOException e) {
			log.error("Could not load origin configuration: " + e);
			throw new AAException("Could not load origin configuration.");
		}

		//Load global configuration properties
		configuration = new ShibbolethOriginConfig(parser.getDocument().getDocumentElement());

		//Load name mappings
		NodeList itemElements =
			parser.getDocument().getDocumentElement().getElementsByTagNameNS(
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
			targetMapper =
				new ServiceProviderMapper(
					parser.getDocument().getDocumentElement(),
					configuration,
					credentials,
					nameMapper);
		} catch (ServiceProviderMapperException e) {
			log.error("Could not load origin configuration: " + e);
			throw new AAException("Could not load origin configuration.");
		}

		/*
				//Set defaults
				Properties defaultProps = new Properties();
				defaultProps.setProperty(
					"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path",
					"/conf/arps/");
				defaultProps.setProperty(
					"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
					"/conf/resolver.xml");
				defaultProps.setProperty(
					"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
					"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository");
				defaultProps.setProperty("edu.internet2.middleware.shibboleth.audiences", "urn:mace:inqueue");
				defaultProps.setProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.passThruErrors", "false");
		
				//Load from file
				Properties properties = new Properties(defaultProps);
				String propertiesFileLocation = getInitParameter("OriginPropertiesFile");
				if (propertiesFileLocation == null) {
					propertiesFileLocation = "/conf/origin.properties";
				}
				try {
					log.debug("Loading Configuration from (" + propertiesFileLocation + ").");
					properties.load(new ShibResource(propertiesFileLocation, this.getClass()).getInputStream());
		
					//Make sure we have all required parameters
					StringBuffer missingProperties = new StringBuffer();
					String[] requiredProperties =
						{
							"edu.internet2.middleware.shibboleth.hs.HandleServlet.siteName",
							"edu.internet2.middleware.shibboleth.aa.AAServlet.authorityName",
							"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
							"edu.internet2.middleware.shibboleth.audiences" };
		
					for (int i = 0; i < requiredProperties.length; i++) {
						if (properties.getProperty(requiredProperties[i]) == null) {
							missingProperties.append("\"");
							missingProperties.append(requiredProperties[i]);
							missingProperties.append("\" ");
						}
					}
					if (missingProperties.length() > 0) {
						log.error(
							"Missing configuration data.  The following configuration properites have not been set: "
								+ missingProperties.toString());
						throw new AAException("Missing configuration data.");
					}
		
				} catch (IOException e) {
					log.error("Could not load AA servlet configuration: " + e);
					throw new AAException("Could not load AA servlet configuration.");
				}
		
				if (log.isDebugEnabled()) {
					ByteArrayOutputStream debugStream = new ByteArrayOutputStream();
					PrintStream debugPrinter = new PrintStream(debugStream);
					properties.list(debugPrinter);
					log.debug(
						"Runtime configuration parameters: " + System.getProperty("line.separator") + debugStream.toString());
					try {
						debugStream.close();
					} catch (IOException e) {
						log.error("Encountered a problem cleaning up resources: could not close debug stream.");
					}
				}
		
				//Be nice and trim "extra" whitespace from config properties
				Enumeration propNames = properties.propertyNames();
				while (propNames.hasMoreElements()) {
					String propName = (String) propNames.nextElement();
					if (properties.getProperty(propName, "").matches(".+\\s$")) {
						log.debug("The configuration property (" + propName + ") contains trailing whitespace.  Trimming... ");
						properties.setProperty(propName, properties.getProperty(propName).trim());
					}
				}
		
				return properties;
				*/
	}
	private DOMParser loadParser(boolean schemaChecking) throws AAException {

		DOMParser parser = new DOMParser();

		if (!schemaChecking) {
			return parser;
		}

		try {
			parser.setFeature("http://xml.org/sax/features/validation", true);
			parser.setFeature("http://apache.org/xml/features/validation/schema", true);

			parser.setEntityResolver(new EntityResolver() {
				public InputSource resolveEntity(String publicId, String systemId) throws SAXException {
					log.debug("Resolving entity for System ID: " + systemId);
					if (systemId != null) {
						StringTokenizer tokenString = new StringTokenizer(systemId, "/");
						String xsdFile = "";
						while (tokenString.hasMoreTokens()) {
							xsdFile = tokenString.nextToken();
						}
						if (xsdFile.endsWith(".xsd")) {
							InputStream stream;
							try {
								stream = new ShibResource("/schemas/" + xsdFile, this.getClass()).getInputStream();
							} catch (IOException ioe) {
								log.error("Error loading schema: " + xsdFile + ": " + ioe);
								return null;
							}
							if (stream != null) {
								return new InputSource(stream);
							}
						}
					}
					return null;
				}
			});

			parser.setErrorHandler(new ErrorHandler() {
				public void error(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
				public void fatalError(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
				public void warning(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
			});

		} catch (SAXException e) {
			log.error("Unable to setup a workable XML parser: " + e);
			throw new AAException("Unable to setup a workable XML parser.");
		}
		return parser;
	}

	public void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		MDC.put("serviceId", "[AA] " + new SAMLIdentifier().toString());
		MDC.put("remoteAddr", req.getRemoteAddr());
		log.info("Handling request.");

		StringBuffer credentialName = new StringBuffer();
		SAMLRequest samlRequest = binding.receive(req, credentialName);
		if (samlRequest.getQuery() == null || !(samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
			//TODO better exception
			throw new SAMLException(
				SAMLException.REQUESTER,
				"AASaml.receive() can only respond to a SAML Attribute Query");
		}
		SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

		try {

			RelyingParty relyingParty = targetMapper.getRelyingParty(attributeQuery.getResource());

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

//TODO fix logging
			//log.info("Attribute Query Handle for this request: (" + saml.getHandle() + ").");
			
			Principal principal = null;
			if (attributeQuery.getSubject().getName().getName().equalsIgnoreCase("foo")) {
				// for testing
				principal = new AuthNPrincipal("test-handle");
			} else {
				principal = handleRepository.getPrincipal(attributeQuery.getSubject().getName().getName()), attributeQuery.getSubject().getName().getFormat());
			}

			URL resource = null;
			try {
				if (attributeQuery.getResource() != null)
					resource = new URL(attributeQuery.getResource());
			} catch (MalformedURLException mue) {
				log.error(
					"Request contained an improperly formatted resource identifier.  Attempting to "
						+ "handle request without one.");
			}

			if (credentialName == null || credentialName.toString().equals("")) {
				//TODO update messages
				log.info("Request is from an unauthenticated SHAR.");
			} else {
				log.info("Request is from SHAR: (" + credentialName + ").");
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
						resource,
						(URI[]) requestedAttrs.toArray(new URI[0]));
			} else {
				log.info("Request does not designate specific attributes, resolving all available.");
				attrs = responder.getReleaseAttributes(principal, credentialName.toString(), resource);
			}

			log.info("Found " + attrs.length + " attribute(s) for " + principal.getName());
			sendResponse(resp, attrs, samlRequest, null);
			log.info("Successfully responded about " + principal.getName());

			//TODO place transaction log statement here

			//TODO probably need to change a bunch of these messages to not be handle-centric
		} catch (NameIdentifierMappingException e) {
			log.info("Could not associate the Attribute Query Handle with a principal: " + e);
			try {
				QName[] codes =
					{
						SAMLException.REQUESTER,
						new QName(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS, "InvalidHandle")};
				if (configuration
					.getProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.passThruErrors", "false")
					.equals("true")) {
					saml.fail(
						resp,
						new SAMLException(
							Arrays.asList(codes),
							"The supplied Attribute Query Handle was unrecognized or expired.",
							e));

				} else {
					saml.fail(
						resp,
						new SAMLException(
							Arrays.asList(codes),
							"The supplied Attribute Query Handle was unrecognized or expired."));
				}
				return;
			} catch (Exception ee) {
				log.fatal("Could not construct a SAML error response: " + ee);
				throw new ServletException("Attribute Authority response failure.");
			}

		} catch (Exception e) {
			log.error("Error while processing request: " + e);
			try {
				if (configuration
					.getProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.passThruErrors", "false")
					.equals("true")) {
					saml.fail(resp, new SAMLException(SAMLException.RESPONDER, "General error processing request.", e));
				} else {
					saml.fail(resp, new SAMLException(SAMLException.RESPONDER, "General error processing request."));
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
				samlResponse = new SAMLResponse(samlRequest.getId(), null, null, exception);

			} else {
				// Determine max lifetime, and filter via query if necessary.
				Date now = new Date();
				Date then = null;
				long min = 0;

				if (samlRequest.getQuery() == null || !(samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
					//TODO better exception
					throw new SAMLException(
						SAMLException.REQUESTER,
						"AASaml.receive() can only respond to a SAML Attribute Query");
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

				//TODO double check this stuff
				if (min > 0) {
					then = new Date(now.getTime() + (min * 1000));
				}

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
